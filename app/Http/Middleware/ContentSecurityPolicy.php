<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class ContentSecurityPolicy
{
    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        // 1. CSP Ketat (unsafe-inline dihapus dari style-src)
        $csp = "default-src 'self'; " .
               "script-src 'self'; " . 
               "style-src 'self'; " . // <-- Sudah diperbaiki
               "img-src 'self' data:; " .
               "font-src 'self' data:; " .
               "base-uri 'self'; " .
               "form-action 'self'; " .
               "frame-ancestors 'none'; " .
               "upgrade-insecure-requests;"; 

        if (method_exists($response, 'header')) {
            $response->headers->set('Content-Security-Policy', $csp);
            
            // 2. Menambahkan Anti-MIME-Sniffing
            $response->headers->set('X-Content-Type-Options', 'nosniff');
        }

        // 3. Menghapus kebocoran versi PHP (X-Powered-By)
        $response->headers->remove('X-Powered-By');
        if (function_exists('header_remove')) {
            // Berlapis pakai fungsi native PHP buat jaga-jaga kalau settingan server (php.ini) ngeyel
            header_remove('X-Powered-By');
        }

        return $response;
    }
}