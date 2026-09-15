"""Static identity strings used to impersonate a Mac to Apple's GrandSlam service.

These mirror what AltServer / pypush send. Apple tracks some of these, so they are
kept stable and Mac-like. The volatile per-request machine data (X-Apple-I-MD*) comes
from the anisette server, not from here.
"""

# Sent as the GsService2 User-Agent.
GSA_USER_AGENT = "akd/1.0 CFNetwork/1494.0.7 Darwin/23.4.0"

# Identifies us as a specific Mac model + OS + AuthKit build. NOTE: Apple's edge rejects
# requests whose client info names the Xcode GrandSlam identity (com.apple.dt.Xcode) with
# HTTP 503 + an HTML error page (observed 2026-09); this is the Messages-app identity
# rustpush declares for the same calls instead.
GSA_CLIENT_INFO = (
    "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> "
    "<com.apple.AuthKit/1 (com.apple.MobileSMS/1262.500.151.1.2)>"
)

# Default anisette server (SideStore ecosystem). Override with ICP_ANISETTE_URL.
DEFAULT_ANISETTE_URL = "http://localhost:6969"

GSA_ENDPOINT = "https://gsa.apple.com/grandslam/GsService2"
