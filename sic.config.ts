/**
 * SIC — Security Intelligence Center
 * User-facing config schema. Copy to sic.config.json and fill in your values,
 * or set equivalent environment variables (env vars take precedence).
 */

export interface SicConfig {
  engine: {
    /** Host the Flask server binds to. Default: "127.0.0.1" */
    host: string;
    /** Port the Flask server listens on. Default: 9888 */
    port: number;
  };
  security: {
    /** CIDR ranges allowed to reach the admin UI. Default: loopback only. */
    ipAllowlist: string[];
    /** If true, deny all IPs not in ipAllowlist. Default: true */
    denyDefault: boolean;
  };
  alerts: {
    /** Discord webhook URL (env: DISCORD_WEBHOOK_URL) */
    discord?: string;
    /** Slack incoming webhook URL (env: SLACK_WEBHOOK_URL) */
    slack?: string;
    /** Generic HTTPS webhook URL (env: SIC_WEBHOOK_URL) */
    webhook?: string;
    /** Email alert config (env: SIC_ALERT_EMAIL, RESEND_API_KEY, SIC_SMTP_*) */
    email?: {
      to: string[];
      from?: string;
    };
    /** Send each unique finding alert only once per 30 days. Default: true */
    firstFailureOnly: boolean;
  };
  scan: {
    /** Tool timeout in seconds. Default: 300 */
    defaultTimeout: number;
    /** Max parallel scan processes. Default: 4 */
    maxParallel: number;
  };
  ui: {
    /** Dashboard accent hex color (env: SIC_ACCENT_COLOR). Default: "#e94560" */
    accentColor: string;
  };
}

export const defaultConfig: SicConfig = {
  engine: { host: "127.0.0.1", port: 9888 },
  security: { ipAllowlist: ["127.0.0.1/8", "::1"], denyDefault: true },
  alerts: { firstFailureOnly: true },
  scan: { defaultTimeout: 300, maxParallel: 4 },
  ui: { accentColor: "#e94560" },
};
