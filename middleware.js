export const config = {
  // Run on every request so no path can bypass auth.
  matcher: '/:path*',
};

// Constant-time string comparison to avoid leaking length/content via timing.
function safeEqual(a, b) {
  const enc = new TextEncoder();
  const bufA = enc.encode(a);
  const bufB = enc.encode(b);
  if (bufA.length !== bufB.length) {
    // Still compare against something to keep timing roughly constant.
    let diff = 1;
    for (let i = 0; i < bufA.length; i++) diff |= bufA[i] ^ (bufB[i] ?? 0);
    return false;
  }
  let diff = 0;
  for (let i = 0; i < bufA.length; i++) diff |= bufA[i] ^ bufB[i];
  return diff === 0;
}

export default function middleware(request) {
  const expectedUser = process.env.BASIC_AUTH_USER;
  const expectedPass = process.env.BASIC_AUTH_PASS;

  // Fail closed: if credentials aren't configured, deny everything.
  if (!expectedUser || !expectedPass) {
    return new Response('Server auth not configured.', { status: 503 });
  }

  const header = request.headers.get('authorization');
  if (header) {
    const [scheme, encoded] = header.split(' ');
    if (scheme === 'Basic' && encoded) {
      let decoded = '';
      try {
        decoded = atob(encoded);
      } catch {
        decoded = '';
      }
      const sep = decoded.indexOf(':');
      if (sep !== -1) {
        const user = decoded.slice(0, sep);
        const pass = decoded.slice(sep + 1);
        const okUser = safeEqual(user, expectedUser);
        const okPass = safeEqual(pass, expectedPass);
        if (okUser && okPass) {
          return; // authenticated — continue to the requested asset
        }
      }
    }
  }

  return new Response('Authentication required.', {
    status: 401,
    headers: {
      'WWW-Authenticate': 'Basic realm="S@S Report", charset="UTF-8"',
      'Cache-Control': 'no-store',
    },
  });
}
