"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { baseNavItems } from "@/lib/navigation";
import styles from "./ReportingShell.module.css";

const items = [...baseNavItems, { label: "Reporting", href: "/reporting" }, { label: "Settings", href: "/settings" }];

export default function ReportingNav() {
  const pathname = usePathname();
  return <nav aria-label="Main navigation" className={styles.navigation}>
    <Link href="/dashboard" className={styles.brand}>GMI <span>VULN</span></Link>
    <div className={styles.navLinks}>
      {items.map(item => {
        const active = item.href === "/reporting" ? pathname === "/reporting" || pathname.startsWith("/report/") : pathname === item.href || pathname.startsWith(`${item.href}/`);
        return <Link key={item.href} href={item.href} aria-current={active ? "page" : undefined} className={active ? styles.navActive : styles.navLink}>{item.label}</Link>;
      })}
    </div>
  </nav>;
}
