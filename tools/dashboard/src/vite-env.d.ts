// Optional defaults for local development (`.env.local`, or the environment of `npm run dev`); used only when the
// browser has no stored address or token. See README.md.
interface ImportMetaEnv {
  /** server-host's address, e.g. http://192.0.2.10:27180. */
  readonly VITE_HOST_URL?: string;
  /** Its admin token; read by the dev server only, never put into a build. */
  readonly VITE_HOST_TOKEN?: string;
}
