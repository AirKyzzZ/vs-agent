import { defineConfig, mergeConfig } from 'vitest/config'

import rootConfig from '../../vitest.config'

export default mergeConfig(
  rootConfig,
  defineConfig({
    test: {
      // Register the native askar backend before @credo-ts/askar's KMS module
      // snapshots the (otherwise undefined) shared binding.
      setupFiles: ['tests/setup.askar.ts'],
      // askar-nodejs native bindings race when multiple test files instantiate
      // Credo agents concurrently; serialise test files.
      fileParallelism: false,
    },
  }),
)
