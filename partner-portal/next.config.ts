import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  transpilePackages: ["snarkjs"],
  turbopack: {},
  async rewrites() {
    const kycOrigin = process.env.KYC_INTERNAL_URL || "http://localhost:8000";
    const camaraOrigin = process.env.CAMARA_INTERNAL_URL || "http://localhost:8004";
    const dashboardOrigin = process.env.DASHBOARD_INTERNAL_URL || "http://localhost:8003";

    return [
      {
        source: "/api/kyc/:path*",
        destination: `${kycOrigin}/api/kyc/:path*`,
      },
      {
        source: "/api/camara/:path*",
        destination: `${camaraOrigin}/:path*`,
      },
      {
        source: "/dashboard/:path*",
        destination: `${dashboardOrigin}/:path*`,
      },
    ];
  },
};

export default nextConfig;
