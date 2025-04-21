declare module '@vue-flow/core' {
  import { Component } from 'vue'
  
  export const VueFlow: Component
  export const Background: Component
  export const Controls: Component
  export const MiniMap: Component
  export const BaseEdge: Component
  export const Handle: Component
  
  export interface EdgeProps {
    id: string
    sourceX: number
    sourceY: number
    targetX: number
    targetY: number
    sourcePosition: string
    targetPosition: string
    data?: Record<string, any>
  }

  export interface BezierPathOptions {
    sourceX: number
    sourceY: number
    sourcePosition: string
    targetX: number
    targetY: number
    targetPosition: string
    curvature?: number
  }

  export interface BezierPathResult {
    path: string
    labelX?: number
    labelY?: number
  }

  export function getBezierPath(options: BezierPathOptions): BezierPathResult

  export function useVueFlow(): {
    fitView: (options?: { padding?: number }) => void
    getEdgeParams: (params: {
      sourceX: number
      sourceY: number
      sourcePosition: string
      targetX: number
      targetY: number
      targetPosition: string
    }) => {
      sourceX: number
      sourceY: number
      targetX: number
      targetY: number
      sourcePosition: string
      targetPosition: string
    }
  }
  
  export const Position: {
    Left: string
    Right: string
    Top: string
    Bottom: string
  }
} 