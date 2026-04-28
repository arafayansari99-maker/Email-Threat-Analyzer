import { useState, useCallback, useRef } from 'react'

let _queueId = 0

export function useAnalysisQueue(onComplete) {
  const [jobs, setJobs] = useState([])
  const dispatchRef = useRef(0)

  const addJob = useCallback((filename) => {
    const id = ++_queueId
    const job = {
      id,
      filename,
      status: 'queued',   // queued | processing | done | error
      progress: 0,
      result: null,
      error: null,
      addedAt: Date.now(),
    }
    setJobs(prev => [...prev, job])
    return id
  }, [])

  const updateJob = useCallback((id, patch) => {
    setJobs(prev => prev.map(j => j.id === id ? { ...j, ...patch } : j))
  }, [])

  const removeJob = useCallback((id) => {
    setJobs(prev => prev.filter(j => j.id !== id))
  }, [])

  const clearDone = useCallback(() => {
    setJobs(prev => prev.filter(j => j.status !== 'done' && j.status !== 'error'))
  }, [])

  // Simulate queue processing (non-blocking)
  const simulateJob = useCallback((jobId, totalFiles = 1, onEach) => {
    const STEPS = 4
    let step = 0
    const tick = () => {
      step++
      const progress = Math.round((step / STEPS) * 100)
      updateJob(jobId, { progress, status: step < STEPS ? 'processing' : 'done' })
      onEach?.({ progress, step, status: step < STEPS ? 'processing' : 'done' })
      if (step < STEPS) {
        setTimeout(tick, 600 + Math.random() * 400)
      } else {
        setTimeout(() => {
          updateJob(jobId, { status: 'done', progress: 100 })
          onComplete?.({ jobId, status: 'done', filename: jobs.find(j => j.id === jobId)?.filename })
        }, 300)
      }
    }
    setTimeout(tick, 200)
  }, [updateJob, onComplete, jobs])

  return {
    jobs,
    addJob,
    updateJob,
    removeJob,
    clearDone,
    simulateJob,
    totalJobs: jobs.length,
    pendingJobs: jobs.filter(j => j.status === 'queued' || j.status === 'processing').length,
    doneJobs: jobs.filter(j => j.status === 'done').length,
  }
}