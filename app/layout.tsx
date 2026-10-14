import type { Metadata } from "next"
import { Outfit } from "next/font/google"
import "./globals.css"
import Providers from "@/components/Providers"

// Feature flags must come from the running server, including on full reload.
export const dynamic = "force-dynamic"

const outfit = Outfit({ subsets: ["latin"], variable: "--font-outfit", display: "swap" })

export const metadata: Metadata = {
  title: "Vuln | GMI Vulnerability Console",
  description: "GMI Vulnerability Console",
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className={outfit.variable}>
      <body>
        <Providers initialCapabilities={{ enabled: (process.env.ELASTIC_VULN_ENABLED ?? "true") === "true", remediationEnabled: (process.env.ELASTIC_VULN_ENABLED ?? "true") === "true" && process.env.VULN_REMEDIATION_UI === "true" }}>{children}</Providers>
      </body>
    </html>
  )
}
