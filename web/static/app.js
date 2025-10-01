async function postJSON(url, payload) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

function formatResults(obj) {
  if (!obj) return 'No results';
  const entries = Object.entries(obj);
  if (entries.length === 0) return 'No results';
  return entries.map(([k,v]) => `${k}\n  \\---> ${v}`).join('\n');
}

document.getElementById('lookup-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const api = document.getElementById('apiInput').value.trim();
  const pre = document.getElementById('lookupResult');
  pre.textContent = 'Looking up...';
  try {
    const data = await postJSON('/api/lookup', { api });
    pre.textContent = formatResults(data.results);
  } catch (err) {
    pre.textContent = `Error: ${err.message}`;
  }
});

document.getElementById('analyze-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = document.getElementById('peFile');
  const verbose = document.getElementById('verboseAnalyze').checked;
  const exportResult = document.getElementById('exportResult').checked;
  const pre = document.getElementById('analyzeResult');
  if (!input.files || input.files.length === 0) {
    pre.textContent = 'Please choose a PE file first.';
    return;
  }
  const form = new FormData();
  form.append('file', input.files[0]);
  pre.textContent = 'Analyzing... this may take a moment';
  try {
    if (verbose) {
      // Stream Server-Sent Events for live logs
      const url = `/api/analyze?verbose=true&export=${exportResult}&stream=true`;
      const res = await fetch(url, { method: 'POST', body: form });
      if (!res.ok || !res.body) throw new Error(await res.text());
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      pre.textContent = '';
      const collected = [];

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        // SSE frames separated by double newline
        const parts = buffer.split('\n\n');
        buffer = parts.pop();
        for (const frame of parts) {
          const lines = frame.split('\n');
          let event = 'message';
          let data = '';
          for (const line of lines) {
            if (line.startsWith('event:')) event = line.slice(6).trim();
            else if (line.startsWith('data:')) data += line.slice(5).trimStart() + '\n';
          }
          if (event === 'hit') {
            pre.textContent += data + '\n';
            collected.push(data.trim());
          } else if (event === 'log') {
            pre.textContent += data + '\n';
          } else if (event === 'done') {
            pre.textContent += '\nCompleted.';
            if (exportResult && collected.length > 0) {
              const ts = new Date().toISOString().replace(/[:.]/g, '-');
              const filename = `APIE_report_${ts}.txt`;
              const header = 'A-PIE analysis report (streamed)\n\n';
              const content = header + collected.join('\n');
              const blob = new Blob([content], { type: 'text/plain' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = filename;
              document.body.appendChild(a);
              a.click();
              document.body.removeChild(a);
              URL.revokeObjectURL(url);
            }
          }
        }
      }
      return;
    }

    // Non-verbose fast JSON path
    const res = await fetch(`/api/analyze?verbose=false&export=${exportResult}`, { method: 'POST', body: form });
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    pre.textContent = formatResults(data.results);
    if (exportResult) {
      const ts = new Date().toISOString().replace(/[:.]/g, '-');
      const filename = `APIE_report_${ts}.txt`;
      const header = 'A-PIE analysis report\n\n';
      const lines = Object.entries(data.results || {}).map(([k,v]) => `${k}\n  \\---> ${v}`);
      const content = header + (lines.length ? lines.join('\n') : 'No results');
      const blob = new Blob([content], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }
  } catch (err) {
    pre.textContent = `Error: ${err.message}`;
  }
});


