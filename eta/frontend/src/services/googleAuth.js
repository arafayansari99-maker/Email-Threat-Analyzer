// Google OAuth Service using Google Sign-In SDK
const GOOGLE_CLIENT_ID = process.env.REACT_APP_GOOGLE_CLIENT_ID || '764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com'

const waitForGoogle = () => {
  return new Promise((resolve, reject) => {
    let attempts = 0
    const checkGoogle = () => {
      if (window.google) {
        resolve(window.google)
      } else if (attempts < 50) {
        attempts++
        setTimeout(checkGoogle, 100)
      } else {
        reject(new Error('Google SDK failed to load'))
      }
    }
    checkGoogle()
  })
}

export const initGoogleSignIn = async (callback) => {
  try {
    const google = await waitForGoogle()

    google.accounts.id.initialize({
      client_id: GOOGLE_CLIENT_ID,
      callback: callback,
      auto_select: false,
    })
  } catch (err) {
    console.error('Failed to initialize Google Sign-In:', err)
  }
}

export const renderGoogleButton = async (elementId) => {
  try {
    const google = await waitForGoogle()
    const element = document.getElementById(elementId)

    if (!element) {
      console.error(`Element with id ${elementId} not found`)
      return
    }

    google.accounts.id.renderButton(element, {
      type: 'standard',
      size: 'large',
      theme: 'dark',
      text: 'continue_with',
      width: '100%',
    })
  } catch (err) {
    console.error('Failed to render Google button:', err)
  }
}

export const handleGoogleResponse = async (response, onSuccess, onError) => {
  try {
    const credential = response.credential
    if (!credential) {
      onError('No credential received from Google')
      return
    }

    // Send token to backend for verification
    const backendResponse = await fetch('http://localhost:8000/auth/google', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ token: credential }),
    })

    const data = await backendResponse.json()

    if (!backendResponse.ok) {
      onError(data.detail || 'Google authentication failed')
      return
    }

    // Store token and user info
    localStorage.setItem('token', data.access_token)
    localStorage.setItem('user', JSON.stringify(data.user))

    onSuccess(data)
  } catch (error) {
    console.error('Google auth error:', error)
    onError(error.message)
  }
}

export const revokeGoogleAccess = () => {
  if (window.google) {
    window.google.accounts.id.revoke(localStorage.getItem('googleEmail'), () => {
      console.log('Google access revoked')
    })
  }
}
