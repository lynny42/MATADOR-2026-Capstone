import "./globals.css";

export const metadata = {
  title: "MATADOR MA Dashboard",
  description: "Ground-station MA integrated detection dashboard"
};

export default function RootLayout({ children }) {
  return (
    <html lang="ko">
      <body>{children}</body>
    </html>
  );
}
