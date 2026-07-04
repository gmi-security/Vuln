import type { Metadata } from "next"
import "./globals.css"

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
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
