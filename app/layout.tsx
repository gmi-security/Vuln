import type { Metadata } from "next"
import { Outfit } from "next/font/google"
import "./globals.css"
import Providers from "@/components/Providers"

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
        <Providers>{children}</Providers>
      </body>
    </html>
  )
}
