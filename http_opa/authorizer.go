package httpopa

import (
	"context"
	"encoding/json"
	"net/http"

	"fmt"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"github.com/infobloxopen/atlas-authz-middleware/common"
	az "github.com/infobloxopen/atlas-authz-middleware/common/authorizer"
	commonClaim "github.com/infobloxopen/atlas-authz-middleware/common/claim"
	"github.com/infobloxopen/atlas-authz-middleware/common/opautil"
	"github.com/infobloxopen/atlas-authz-middleware/http_opa/exception"
	"github.com/infobloxopen/atlas-authz-middleware/http_opa/util"
	"github.com/infobloxopen/atlas-authz-middleware/pkg/opa_client"
	log "github.com/sirupsen/logrus"
	"go.opencensus.io/trace"
	"go.uber.org/multierr"
	"google.golang.org/grpc"
)

var (
	SERVICENAME = "opa"
)

type httpAuthorizer struct {
	application          string
	clienter             opa_client.Clienter
	opaEvaluator         az.OpaEvaluator
	decisionInputHandler az.DecisionInputHandler
	claimsVerifier       az.ClaimsVerifier
	entitledServices     []string
	acctEntitlementsApi  string
	endpointModifier     *EndpointModifier
}

var defDecisionInputer = new(az.DefaultDecisionInputer)

func NewHttpAuthorizer(application string, opts ...Option) az.Authorizer {
	cfg := &Config{
		address:              opa_client.DefaultAddress,
		decisionInputHandler: defDecisionInputer,
		claimsVerifier:       commonClaim.UnverifiedClaimFromBearers,
		acctEntitlementsApi:  common.DefaultAcctEntitlementsApiPath,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	//log.Debugf("cfg=%+v", *cfg)

	clienter := cfg.clienter
	if clienter == nil {
		clienter = opa_client.New(cfg.address, opa_client.WithHTTPClient(cfg.httpCli))
	}

	a := httpAuthorizer{
		clienter:             clienter,
		opaEvaluator:         cfg.opaEvaluator,
		application:          application,
		decisionInputHandler: cfg.decisionInputHandler,
		claimsVerifier:       cfg.claimsVerifier,
		entitledServices:     cfg.entitledServices,
		acctEntitlementsApi:  cfg.acctEntitlementsApi,
		endpointModifier:     cfg.endpointModifier,
	}
	return &a
}

func (a *httpAuthorizer) Evaluate(ctx context.Context, endpoint string, req interface{}, opaEvaluator az.OpaEvaluator) (bool, context.Context, error) {

	logger := ctxlogrus.Extract(ctx).WithFields(log.Fields{
		"application": a.application,
	})

	//get bearer from Authorization header
	bearer, err := util.GetBearerFromRequest(req.(*http.Request))
	if err != nil {
		logger.WithError(err).Error("get_bearer_from_request")
		return false, ctx, exception.ErrAbstrForbidden
	}

	claimsVerifier := a.claimsVerifier
	if claimsVerifier == nil {
		claimsVerifier = commonClaim.UnverifiedClaimFromBearers
	}

	rawJWT, errs := claimsVerifier([]string{bearer}, nil)
	if len(errs) > 0 {
		return false, ctx, exception.NewHttpError(
			exception.WithError(multierr.Combine(errs...)),
			exception.WithHttpStatus(http.StatusUnauthorized))
	}

	reqID := util.GetRequestIdFromRequest(req.(*http.Request))

	//if endpoint needs to be mutated
	pargsEndpoint := endpoint
	if a.endpointModifier != nil {
		pargsEndpoint = a.endpointModifier.getModifiedEndpoint(pargsEndpoint)
	}

	opaReq := opautil.Payload{
		Endpoint:    pargsEndpoint,
		FullMethod:  endpoint,
		Application: a.application,
		// FIXME: implement atlas_claims.AuthBearersFromCtx
		JWT:              opautil.RedactJWT(rawJWT),
		RequestID:        reqID,
		EntitledServices: a.entitledServices,
	}

	decisionInput, err := a.decisionInputHandler.GetDecisionInput(ctx, endpoint, req)
	if decisionInput == nil || err != nil {
		logger.WithFields(log.Fields{
			"endpoint": endpoint,
		}).WithError(err).Error("get_decision_input")
		return false, ctx, exception.ErrInvalidArg
	}

	opaReq.DecisionInput = *decisionInput

	opaReqJSON, err := json.Marshal(opaReq)
	if err != nil {
		logger.WithFields(log.Fields{
			"opaReq": opaReq,
		}).WithError(err).Error("opa_request_json_marshal")
		return false, ctx, exception.ErrInvalidArg
	}

	now := time.Now()
	obfuscatedOpaReq := opautil.ShortenPayloadForDebug(opaReq)
	logger.WithFields(log.Fields{
		"opaReq": obfuscatedOpaReq,
	}).Debug("opa_authorization_request")

	// To enable tracing, the context must have a tracer attached
	// to it. See the tracing documentation on how to do this.
	ctx, span := trace.StartSpan(ctx, fmt.Sprint(SERVICENAME, endpoint))
	{
		span.Annotate([]trace.Attribute{
			trace.StringAttribute("in", string(opaReqJSON)),
		}, "in")
	}
	// FIXME: perhaps only inject these fields if this is the default handler

	// If DecisionDocument is empty, the default OPA-configured decision document is queried.
	// In this case, the input payload MUST NOT be encapsulated inside "input".
	// Otherwise for any other non-empty DecisionDocument, even if it's the same as the default
	// OPA-configured decision document, the input payload MUST be encapsulated inside "input".
	// (See comments in testdata/mock_system_main.rego)
	var opaInput interface{}
	opaInput = opaReq
	if len(decisionInput.DecisionDocument) > 0 {
		opaInput = opautil.OPARequest{Input: &opaReq}
	}

	var opaResp opautil.OPAResponse
	err = opaEvaluator(ctxlogrus.ToContext(ctx, logger), decisionInput.DecisionDocument, opaInput, &opaResp)
	// Metrics, logging, tracing handler
	defer func() {
		// opencensus Status is based on gRPC status codes
		// https://pkg.go.dev/go.opencensus.io/trace?tab=doc#Status
		// err == nil will return {Code: 200, Message:""}
		span.SetStatus(trace.Status{
			Code:    int32(grpc.Code(err)),
			Message: grpc.ErrorDesc(err),
		})
		span.End()
		logger.WithFields(log.Fields{
			"opaResp": opaResp,
			"elapsed": time.Since(now),
		}).Debug("authorization_result")
	}()
	if err != nil {
		return false, ctx, err
	}

	// When we POST query OPA without url path, it returns results NOT encapsulated inside "result":
	//   {"allow": true, ...}
	// When we POST query OPA with explicit decision document, it returns results encapsulated inside "result":
	//   {"result":{"allow": true, ...}}
	// (See comments in testdata/mock_system_main.rego)
	// If the JSON result document is nested within "result" wrapper map,
	// we extract the nested JSON document and throw away the "result" wrapper map.
	nestedResultVal, resultIsNested := opaResp["result"]
	if resultIsNested {
		nestedResultMap, ok := nestedResultVal.(map[string]interface{})
		if ok {
			opaResp = opautil.OPAResponse{}
			for k, v := range nestedResultMap {
				opaResp[k] = v
			}
		}
	}

	// Log non-err opa responses
	{
		raw, _ := json.Marshal(opaResp)
		span.Annotate([]trace.Attribute{
			trace.StringAttribute("out", string(raw)),
		}, "out")
	}

	// adding raw entitled_features data to context if present
	//REVIEW: is it needed for http?
	ctx = opaResp.AddRawEntitledFeatures(ctx)

	// adding obligations data to context if present
	//REVIEW: is it needed for http?
	ctx, err = opautil.AddObligations(ctx, opaResp)
	if err != nil {
		logger.WithField("opaResp", fmt.Sprintf("%#v", opaResp)).WithError(err).Error("parse_obligations_error")
	}

	if !opaResp.Allow() {
		return false, ctx, exception.ErrForbidden
	}

	return true, ctx, nil
}

func (a *httpAuthorizer) OpaQuery(ctx context.Context, decisionDocument string, opaReq, opaResp interface{}) error {
	if a.opaEvaluator != nil {
		return a.opaEvaluator(ctx, decisionDocument, opaReq, opaResp)
	}

	logger := ctxlogrus.Extract(ctx)

	// Empty document path is intentional
	// DO NOT hardcode a path here
	err := a.clienter.CustomQuery(ctx, decisionDocument, opaReq, opaResp)
	// TODO: allow overriding logger
	if err != nil {
		httpErr := exception.GrpcToHttpError(err)
		logger.WithError(httpErr).Error("opa_policy_engine_request_error")
		return exception.AbstractError(httpErr)
	}
	logger.WithField("opaResp", opaResp).Debug("opa_policy_engine_response")
	return nil
}
