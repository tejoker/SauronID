import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Static export: the site deploys to any static host (out/ folder).
  output: "export",
  trailingSlash: true,
  images: { unoptimized: true },
};

export default nextConfig;
