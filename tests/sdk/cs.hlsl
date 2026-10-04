RWStructuredBuffer<float4> data : register(u0);
groupshared float4 tile[64];
cbuffer C : register(b0) { uint count; float scale; };
float4 shade(float4 v, uint i) {
  float4 acc = 0;
  [unroll(4)] for (uint k = 0; k < 8; ++k) acc += sin(v * (k + 1) + i) / (k + 1);
  return acc * scale;
}
[numthreads(64, 1, 1)]
void cs_main(uint3 id : SV_DispatchThreadID, uint gi : SV_GroupIndex) {
  float4 v = id.x < count ? data[id.x] : 0;
  tile[gi] = shade(v, id.x);
  GroupMemoryBarrierWithGroupSync();
  [loop] for (uint s = 32; s > 0; s >>= 1) { if (gi < s) tile[gi] += tile[gi + s]; GroupMemoryBarrierWithGroupSync(); }
  if (gi == 0) data[id.x] = tile[0] + WaveActiveSum(v);
}
