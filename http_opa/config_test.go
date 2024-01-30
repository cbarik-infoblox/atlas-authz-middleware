package httpopa

import "testing"

func TestEndpointModifier_defaultModify(t *testing.T) {
	type fields struct {
		DefaultModifyConfig
		Modify func(string) string
	}
	type args struct {
		endpoint string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
	}{
		{
			name: "success",
			fields: fields{
				DefaultModifyConfig: DefaultModifyConfig{
					SegmentsNeeded: 2,
					SegmentStart:   3,
					Prefix:         "wapi",
				},
			},
			args: args{
				endpoint: "GET /nios/v1.2/grid/id",
			},
			want: "GET /wapi/grid/id",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &EndpointModifier{
				DefaultModifyConfig: tt.fields.DefaultModifyConfig,
				Modify:              tt.fields.Modify,
			}
			if got := e.defaultModify(tt.args.endpoint); got != tt.want {
				t.Errorf("EndpointModifier.defaultModify() = %v, want %v", got, tt.want)
			}
		})
	}
}
