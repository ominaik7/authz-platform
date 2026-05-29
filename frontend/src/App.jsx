
import { useEffect, useState } from 'react'

export default function App() {

  const [summary, setSummary] = useState({})
  const [roles, setRoles] = useState([])
  const [findings, setFindings] = useState([])
  const [endpoints, setEndpoints] = useState([])
  const [loading, setLoading] = useState(false)

  const refreshData = () => {
    fetch('http://localhost:8000/summary')
      .then(r => r.json())
      .then(setSummary)

    fetch('http://localhost:8000/roles')
      .then(r => r.json())
      .then(setRoles)

    fetch('http://localhost:8000/findings')
      .then(r => r.json())
      .then(setFindings)

    fetch('http://localhost:8000/endpoints')
      .then(r => r.json())
      .then(setEndpoints)
  }

  useEffect(() => {
    refreshData()
  }, [])

  const uploadBurp = async (e) => {
    const file = e.target.files[0]
    if (!file) return

    setLoading(true)

    const formData = new FormData()
    formData.append('file', file)

    await fetch('http://localhost:8000/upload', {
      method: 'POST',
      body: formData
    })

    refreshData()
    setLoading(false)
  }

  return (
    <div style={{
      background:'#020617',
      color:'white',
      minHeight:'100vh',
      padding:24,
      fontFamily:'Arial'
    }}>
      <h1 style={{fontSize:42}}>
        Authorization Intelligence Platform
      </h1>

      <p style={{color:'#94a3b8'}}>
        Live Burp XML Authorization Intelligence
      </p>

      <div style={{marginTop:20}}>
        <input type="file" onChange={uploadBurp} />
      </div>

      {loading && (
        <div style={{marginTop:20}}>
          Processing Burp XML...
        </div>
      )}

      <div style={{
        display:'grid',
        gridTemplateColumns:'repeat(3,1fr)',
        gap:16,
        marginTop:24
      }}>
        {Object.entries(summary).map(([k,v]) => (
          <div key={k} style={{
            background:'#0f172a',
            padding:20,
            borderRadius:16
          }}>
            <div style={{color:'#94a3b8'}}>{k}</div>
            <div style={{
              fontSize:36,
              fontWeight:'bold'
            }}>{v}</div>
          </div>
        ))}
      </div>

      <div style={{marginTop:40}}>
        <h2>Detected Roles</h2>

        {roles.map((role) => (
          <div key={role.role} style={{
            background:'#0f172a',
            padding:16,
            borderRadius:12,
            marginTop:12
          }}>
            <strong>{role.role}</strong>
            <div>Tier: {role.tier}</div>
            <div>Scope: {role.scope}</div>
            <div>Endpoints: {role.endpoints}</div>
          </div>
        ))}
      </div>

      <div style={{marginTop:40}}>
        <h2>Endpoints</h2>

        {endpoints.slice(0, 20).map((ep, idx) => (
          <div key={idx} style={{
            background:'#0f172a',
            padding:12,
            borderRadius:10,
            marginTop:10
          }}>
            <strong>{ep.method}</strong> {ep.path}
          </div>
        ))}
      </div>

      <div style={{marginTop:40}}>
        <h2>Replay Findings</h2>

        {findings.length === 0 && (
          <div>No findings yet</div>
        )}

        {findings.map((finding, idx) => (
          <div key={idx} style={{
            background:'#0f172a',
            padding:16,
            borderRadius:12,
            marginTop:12
          }}>
            <strong>{finding.type}</strong>
            <div>{finding.endpoint}</div>
            <div>
              {finding.originalRole} → {finding.replayRole}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
