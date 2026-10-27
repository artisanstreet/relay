/**
 * Generated from .env.schema by Varlock for Effect 4. Do not edit by hand.
 */
import * as Config from "effect/Config"
import * as Effect from "effect/Effect"

export const config = Config.all({
  /**
   * Exact https bare origins. Distinct hostnames; never reuse prod for previews.
   */
  "AST_CORE_ORIGIN": Config.String("AST_CORE_ORIGIN"),
  "AST_RELAY_ORIGIN": Config.String("AST_RELAY_ORIGIN"),
})

/** Loads environment values when executed, converting config failures to defects. */
export const generated = config.pipe(Effect.orDie)
