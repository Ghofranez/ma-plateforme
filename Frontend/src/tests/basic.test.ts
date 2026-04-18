import { describe, it, expect } from 'vitest'

describe('Tests basiques', () => {
  it('addition fonctionne', () => {
    expect(1 + 1).toBe(2)
  })

  it('string fonctionne', () => {
    expect("bonjour").toBe("bonjour")
  })

  it('tableau fonctionne', () => {
    expect([1, 2, 3]).toHaveLength(3)
  })
})
