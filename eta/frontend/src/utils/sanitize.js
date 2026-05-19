import DOMPurify from 'dompurify'

/**
 * Sanitize a string before rendering as HTML.
 * Use this anywhere user-generated content is rendered via dangerouslySetInnerHTML.
 */
export function sanitizeHtml(dirty) {
  return DOMPurify.sanitize(dirty ?? '', {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'br', 'p', 'span'],
    ALLOWED_ATTR: ['href', 'title', 'target', 'rel'],
    FORCE_BODY: false,
  })
}

/** Strip all HTML tags — use for plain-text display of user content. */
export function stripHtml(dirty) {
  return DOMPurify.sanitize(dirty ?? '', { ALLOWED_TAGS: [], ALLOWED_ATTR: [] })
}
