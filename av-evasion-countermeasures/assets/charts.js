// MiniAV 免杀反制报告 · 图表逻辑（ECharts）
(function () {
  var style = getComputedStyle(document.documentElement);
  var accent = style.getPropertyValue('--accent').trim();
  var accent2 = style.getPropertyValue('--accent2').trim();
  var ink = style.getPropertyValue('--ink').trim();
  var muted = style.getPropertyValue('--muted').trim();
  var rule = style.getPropertyValue('--rule').trim();
  var bg2 = style.getPropertyValue('--bg2').trim();

  // ---- 图 2 · 行为链规则权重分布 ----
  var weights = [
    { name: 'SBX-AntiDefense', value: 3, isNew: false },
    { name: 'SBX-AmsiTamper', value: 3, isNew: true },
    { name: 'SBX-CredAccess', value: 2, isNew: false },
    { name: 'SBX-Persistence', value: 2, isNew: false },
    { name: 'SBX-Macro-AutoExec', value: 2, isNew: false },
    { name: 'SBX-Remote-Download', value: 2, isNew: false },
    { name: 'SBX-Direct-Syscall', value: 2, isNew: true },
    { name: 'SBX-Shellcode-Decode', value: 2, isNew: true },
    { name: 'SBX-EtwTamper', value: 2, isNew: true },
    { name: 'SBX-Unhook', value: 2, isNew: true },
    { name: 'SBX-Dynamic-Exec', value: 1, isNew: false },
    { name: 'SBX-Encoded-Payload', value: 1, isNew: false },
    { name: 'SBX-Recon', value: 1, isNew: false },
    { name: 'SBX-Memory-Exec', value: 1, isNew: true },
    { name: 'SBX-AntiSandbox', value: 1, isNew: true }
  ];
  var chartW = echarts.init(document.getElementById('chart-weights'), null, { renderer: 'svg' });
  chartW.setOption({
    animation: false,
    tooltip: { trigger: 'axis', appendToBody: true, axisPointer: { type: 'shadow' } },
    grid: { left: 180, right: 40, top: 40, bottom: 40 },
    legend: {
      data: ['原有规则', '本次新增反制规则'],
      textStyle: { color: muted, fontSize: 12 },
      top: 0
    },
    xAxis: {
      type: 'value', name: '权重', nameTextStyle: { color: muted },
      max: 3.5,
      axisLabel: { color: muted }, splitLine: { lineStyle: { color: rule } }
    },
    yAxis: {
      type: 'category', inverse: true,
      data: weights.map(function (d) { return d.name; }),
      axisLabel: { color: ink, fontFamily: 'JetBrains Mono, Consolas, monospace', fontSize: 11 },
      axisLine: { lineStyle: { color: rule } }
    },
    series: [{
      type: 'bar',
      barWidth: 16,
      itemStyle: { borderRadius: [0, 3, 3, 0] },
      data: weights.map(function (d) { return { value: d.value, itemStyle: { color: d.isNew ? accent2 : accent } }; }),
      label: { show: true, position: 'right', color: muted, fontSize: 11 }
    }]
  });
  window.addEventListener('resize', function () { chartW.resize(); });

  // ---- 图 3 · 覆盖矩阵热力图 ----
  var families = ['直接系统调用 / HellsGate 族', 'AMSI 篡改', 'ETW 致盲', 'ntdll 解钩', '编码伪装 (UUID/IP/MAC)', 'VEH / 注入加载', '反沙箱 (T1497)'];
  var layers = ['YARA 静态规则', '行为链评分', 'PE 启发式'];
  var coverData = [
    [0, 0, 2], [0, 1, 2], [0, 2, 1],
    [1, 0, 2], [1, 1, 2], [1, 2, 0],
    [2, 0, 2], [2, 1, 2], [2, 2, 0],
    [3, 0, 2], [3, 1, 2], [3, 2, 0],
    [4, 0, 2], [4, 1, 2], [4, 2, 0],
    [5, 0, 2], [5, 1, 1], [5, 2, 2],
    [6, 0, 0], [6, 1, 1], [6, 2, 2]
  ];
  var chartC = echarts.init(document.getElementById('chart-coverage'), null, { renderer: 'svg' });
  chartC.setOption({
    animation: false,
    tooltip: {
      position: 'top', appendToBody: true,
      formatter: function (p) {
        var v = p.value[2];
        var t = v === 2 ? '主检出（专门规则）' : (v === 1 ? '辅助覆盖（组合条件）' : '该层不适用');
        return families[p.value[1]] + '<br/>' + layers[p.value[0]] + ' : ' + t;
      }
    },
    grid: { left: 200, right: 60, top: 30, bottom: 70 },
    xAxis: {
      type: 'category', data: layers,
      axisLabel: { color: ink, fontSize: 12, interval: 0 },
      splitArea: { show: false }, axisLine: { lineStyle: { color: rule } }
    },
    yAxis: {
      type: 'category', data: families, inverse: true,
      axisLabel: { color: ink, fontSize: 11.5 },
      splitArea: { show: false }, axisLine: { lineStyle: { color: rule } }
    },
    visualMap: {
      min: 0, max: 2, calculable: false, orient: 'horizontal',
      left: 'center', bottom: 0,
      itemHeight: 90, itemWidth: 14,
      text: ['主检出', '不适用'], textStyle: { color: muted },
      inRange: { color: [bg2, accent2, accent] },
      outOfRange: { color: 'transparent' }
    },
    series: [{
      type: 'heatmap',
      data: coverData,
      label: {
        show: true,
        formatter: function (p) {
          var v = p.value[2];
          return v === 2 ? '主检出' : (v === 1 ? '辅助' : '—');
        },
        color: ink, fontSize: 11
      },
      itemStyle: { borderColor: rule, borderWidth: 1 }
    }]
  });
  window.addEventListener('resize', function () { chartC.resize(); });
})();
