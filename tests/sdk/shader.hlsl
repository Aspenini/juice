cbuffer Params : register(b0) { float4x4 world; float4 tint; float time; };
Texture2D tex : register(t0); SamplerState smp : register(s0);
struct VSIn { float3 pos : POSITION; float2 uv : TEXCOORD0; };
struct PSIn { float4 pos : SV_Position; float2 uv : TEXCOORD0; };
PSIn vs_main(VSIn i) { PSIn o; o.pos = mul(float4(i.pos, 1), world); o.uv = i.uv + float2(sin(time), cos(time)) * 0.1; return o; }
float4 ps_main(PSIn i) : SV_Target {
  float4 c = tex.Sample(smp, i.uv) * tint;
  [loop] for (int k = 0; k < 4; ++k) c.rgb = lerp(c.rgb, c.gbr, 0.25 * k);
  return saturate(c);
}
