// Virtual List component for rendering large lists efficiently
import { useState, useEffect, useRef, useMemo, useCallback, createElement } from 'react'

const DEFAULT_ITEM_HEIGHT = 48

export function VirtualList({
  items,
  itemHeight = DEFAULT_ITEM_HEIGHT,
  overscan = 3,
  renderItem,
  keyExtractor = (item, index) => item?.id ?? index,
  className,
  containerStyle,
  onEndReached,
  endReachedThreshold = 200,
}) {
  const [scrollTop, setScrollTop]         = useState(0)
  const [containerHeight, setContainerHeight] = useState(0)
  const containerRef = useRef(null)

  useEffect(() => {
    const container = containerRef.current
    if (!container) return
    const ro = new ResizeObserver(([entry]) => {
      setContainerHeight(entry.borderBoxSize[0].blockSize)
    })
    ro.observe(container)
    return () => ro.disconnect()
  }, [])

  const handleScroll = useCallback((e) => {
    const t = e.target
    setScrollTop(t.scrollTop)
    if (onEndReached) {
      const { scrollTop: st, scrollHeight: sh, clientHeight: ch } = t
      if (sh - st - ch < endReachedThreshold) onEndReached()
    }
  }, [onEndReached, endReachedThreshold])

  const { startIndex, visibleItems, innerStyle } = useMemo(() => {
    const start        = Math.max(0, Math.floor(scrollTop / itemHeight) - overscan)
    const visibleCount = Math.ceil((containerHeight || itemHeight) / itemHeight) + overscan * 2
    const end          = Math.min(items.length - 1, start + visibleCount)
    return {
      startIndex:   start,
      visibleItems: items.slice(start, end + 1),
      innerStyle: {
        height:     items.length * itemHeight,
        paddingTop: start * itemHeight,
        position:   'relative',
      },
    }
  }, [scrollTop, containerHeight, itemHeight, overscan, items])

  return createElement(
    'div',
    {
      ref:      containerRef,
      className: `virtual-list${className ? ` ${className}` : ''}`,
      style:    { overflow: 'auto', height: containerHeight || '100%', ...containerStyle },
      onScroll: handleScroll,
    },
    createElement(
      'div',
      { style: innerStyle },
      visibleItems.map((item, index) =>
        createElement(
          'div',
          { key: keyExtractor(item, startIndex + index), style: { height: itemHeight } },
          renderItem(item, startIndex + index)
        )
      )
    )
  )
}

