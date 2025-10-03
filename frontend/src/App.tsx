import { useEffect, useMemo, useRef, useState } from "react";

function useDebounced<T>(value: T, delay = 250) {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => { const id = setTimeout(() => setDebounced(value), delay); return () => clearTimeout(id); }, [value, delay]);
  return debounced;
}

async function fetchJSON(url: string) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export default function App() {
  const [mode, setMode] = useState<"technique" | "nist">("technique");
  const [query, setQuery] = useState("");
  const debounced = useDebounced(query);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<any | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!debounced || debounced.trim().length < 2) { setData(null); setError(null); return; }
    let active = true;
    setLoading(true); setError(null);
    const url = mode === "technique" ? `/api/technique?q=${encodeURIComponent(debounced)}` : `/api/nist?q=${encodeURIComponent(debounced)}`;
    fetchJSON(url)
      .then((j) => { if (active) setData(j); })
      .catch((e) => { if (active) setError(e.message || "Request failed"); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [debounced, mode]);

  const header = useMemo(() => {
    if (!data) return null;
    return mode === "technique"
      ? (<div><strong>{data.technique || "?"}</strong> — {data.name || "Technique"}</div>)
      : (<div><strong>{data.control || "?"}</strong> — {data.name || "Control"}</div>);
  }, [data, mode]);

  return (
    <div style={{maxWidth: 900, margin: "32px auto", padding: 16, fontFamily: "system-ui, sans-serif"}}>
      <h1>ATT&CK ↔ NIST Mapper</h1>

      <div style={{display: "flex", gap: 8, marginTop: 12, marginBottom: 12}}>
        <button onClick={() => { setMode("technique"); setData(null); setError(null); inputRef.current?.focus(); }}
                style={{padding: "6px 10px", background: mode==="technique"?"#111827":"#e5e7eb", color: mode==="technique"?"#fff":"#111"}}>
          Technique → NIST
        </button>
        <button onClick={() => { setMode("nist"); setData(null); setError(null); inputRef.current?.focus(); }}
                style={{padding: "6px 10px", background: mode==="nist"?"#111827":"#e5e7eb", color: mode==="nist"?"#fff":"#111"}}>
          NIST → Technique
        </button>
        <input ref={inputRef} value={query} onChange={(e)=>setQuery(e.target.value)} placeholder={mode==="technique"?"e.g., T1110":"e.g., AC-2"} style={{flex: 1, padding: "6px 10px"}}/>
        <button onClick={()=>setQuery((v)=>v.trim())}>Search</button>
      </div>

      {!data && !loading && !error && (
        <div style={{color:"#6b7280"}}>Tip: try <code>T1110</code> or <code>AC-2</code>.</div>
      )}

      {loading && (
        <div style={{color:"#6b7280"}}>Loading…</div>
      )}

      {error && (
        <div style={{color:"#b91c1c"}}>{error}</div>
      )}

      {data && (
        <div style={{marginTop: 16, display:"grid", gap: 12}}>
          <div>{header}</div>

          <section style={{border:"1px solid #e5e7eb", borderRadius:8, padding:12}}>
            <h3 style={{marginTop:0}}>Exact mappings</h3>
            {data.exact?.length ? (
              <div>
                {data.exact.map((row: any, i: number) => (
                  <div key={i} style={{padding:"8px 0", borderTop: i? "1px solid #eee":"none"}}>
                    <div><strong>{row.control_id || row.attack_id}</strong> — {row.control_name || row.attack_name}</div>
                    {row.mapping_type && <div style={{color:"#6b7280", fontSize:12}}>{row.mapping_type}</div>}
                  </div>
                ))}
              </div>
            ) : <div style={{color:"#6b7280"}}>No exact results.</div>}
          </section>

          <section style={{border:"1px solid #e5e7eb", borderRadius:8, padding:12}}>
            <h3 style={{marginTop:0}}>Semantic suggestions</h3>
            {data.semantic?.length ? (
              <div>
                {data.semantic.map((row: any, i: number) => (
                  <div key={i} style={{padding:"8px 0", borderTop: i? "1px solid #eee":"none"}}>
                    <div><strong>{row.id}</strong> — {row.name}</div>
                    {typeof row.score === "number" && <div style={{color:"#6b7280", fontSize:12}}>score: {row.score.toFixed(3)}</div>}
                  </div>
                ))}
              </div>
            ) : <div style={{color:"#6b7280"}}>No semantic suggestions.</div>}
          </section>

          <div style={{color:"#6b7280", fontSize:12}}>Data: CTID Mappings Explorer & MITRE ATT&CK</div>
        </div>
      )}
    </div>
  );
}
