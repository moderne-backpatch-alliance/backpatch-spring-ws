/*
 * Copyright 2005-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.ws.soap.addressing.server;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Locale;

import org.springframework.util.StringUtils;
import org.springframework.ws.transport.http.HttpTransportConstants;

/**
 * Default checks applied to an out-of-band reply destination that was supplied by a
 * remote peer, that is a {@code wsa:ReplyTo} or {@code wsa:FaultTo} address taken from an
 * inbound request rather than chosen by the application.
 * <p>
 * Package-private on purpose. The checks are the ones upstream applies to
 * {@code UriSource.REMOTE} destinations, but upstream expresses them through public
 * transport API a consumer configures. Reaching a fix by way of API a consumer has to
 * name would make this artifact something other than a drop-in replacement for its
 * baseline, so the same rules are applied at the one place a peer-supplied address
 * reaches a sender.
 * <p>
 * The rules themselves are Stephane Nicoll's, taken from the {@code UriSource.REMOTE}
 * defaults of spring-ws 4.1.4, and the POLICY is upstream's unchanged -- including what
 * it does not cover, such as IPv6 private ranges and {@code 100.64.0.0/10}. Two inputs
 * are recognised here that upstream's implementation of that policy misses: a
 * bare-decimal host such as {@code 2130706433}, which is a loopback literal, and a host
 * name carrying the DNS root dot, such as {@code localhost.}. Both are destinations
 * upstream states it rejects.
 * <p>
 * Two system properties relax the checks, both defaulting to upstream's own defaults and
 * both read at class initialisation, so they must be set as start-up {@code -D}
 * properties: {@code spring-ws.addressing.allow-site-local-ipv4} re-admits RFC 1918 IPv4
 * literals, and {@code spring-ws.addressing.allow-dns-resolution} resolves host names so
 * the address rules apply to what they resolve to, at the cost of a lookup per reply.
 *
 * @author Moderne Backpatch Alliance
 * @see org.springframework.ws.soap.addressing.server.AddressingEndpointInterceptor
 */
final class RemoteDestinationChecks {

	private static final boolean ALLOW_SITE_LOCAL_IPV4 = Boolean
		.getBoolean("spring-ws.addressing.allow-site-local-ipv4");

	private static final boolean ALLOW_DNS_RESOLUTION = Boolean.getBoolean("spring-ws.addressing.allow-dns-resolution");

	private RemoteDestinationChecks() {
	}

	/**
	 * Whether the given destination is one these checks apply to. Only HTTP destinations
	 * are screened here; other transports carry their own addressing rules and are left
	 * to the sender that supports them.
	 * @param uri the destination URI
	 * @return whether {@link #accepts(URI)} governs this URI
	 */
	static boolean isScreened(URI uri) {
		String scheme = uri.getScheme();
		return HttpTransportConstants.HTTP_URI_SCHEME.equalsIgnoreCase(scheme)
				|| HttpTransportConstants.HTTPS_URI_SCHEME.equalsIgnoreCase(scheme);
	}

	/**
	 * Apply the default checks for a remote-supplied destination.
	 * @param uri the destination URI
	 * @return whether the default checks accept the URI
	 */
	static boolean accepts(URI uri) {
		String hostName = hostName(uri);
		if (hostName == null) {
			return false;
		}
		if ("localhost".equals(hostName) || hostName.endsWith(".localhost")) {
			return false;
		}
		if (!ALLOW_SITE_LOCAL_IPV4 && isSiteLocalIpv4Literal(hostName)) {
			return false;
		}
		InetAddress hostAddress = hostAddress(hostName, ALLOW_DNS_RESOLUTION);
		if (hostAddress != null) {
			if (isLocalAddress(hostAddress)) {
				return false;
			}
			if (!ALLOW_SITE_LOCAL_IPV4 && hostAddress instanceof Inet4Address && hostAddress.isSiteLocalAddress()) {
				return false;
			}
		}
		return true;
	}

	private static boolean isLocalAddress(InetAddress address) {
		return address.isLoopbackAddress() || address.isLinkLocalAddress() || address.isAnyLocalAddress();
	}

	/**
	 * Return the host name of the URI, lower-cased, with the DNS root dot removed.
	 * <p>
	 * Upstream does not strip that dot, and every check below it compares names rather
	 * than addresses, so {@code localhost.} and {@code internal.localhost.} defeat its
	 * localhost guard while resolving to the loopback address exactly as the undotted
	 * forms do. Measured against the released jar: an out-of-band reply to
	 * {@code http://localhost./} reached a real loopback listener. One dot is enough --
	 * {@code localhost..} does not resolve at all -- and a public name is unaffected,
	 * since {@code example.com.} and {@code example.com} are the same host either way.
	 * @return the host name, or {@code null} if the URI has no host name
	 */
	private static String hostName(URI uri) {
		String host = uri.getHost();
		if (!StringUtils.hasText(host)) {
			return null;
		}
		String cleanedHostName = host.toLowerCase(Locale.ROOT);
		if (cleanedHostName.length() >= 2 && cleanedHostName.charAt(0) == '['
				&& cleanedHostName.charAt(cleanedHostName.length() - 1) == ']') {
			cleanedHostName = cleanedHostName.substring(1, cleanedHostName.length() - 1);
		}
		if (cleanedHostName.length() >= 2 && cleanedHostName.charAt(cleanedHostName.length() - 1) == '.') {
			cleanedHostName = cleanedHostName.substring(0, cleanedHostName.length() - 1);
		}
		return cleanedHostName;
	}

	/**
	 * Whether the URI host is an IPv4 address literal in a private (RFC&nbsp;1918) range.
	 * @return {@code true} if the host parses as an IPv4 literal and
	 * {@link InetAddress#isSiteLocalAddress()} is {@code true}; {@code false} for host
	 * names, non-literal hosts, non-IPv4 literals, and public IPv4 literals
	 */
	private static boolean isSiteLocalIpv4Literal(String hostName) {
		InetAddress address = hostAddress(hostName, false);
		return address instanceof Inet4Address && address.isSiteLocalAddress();
	}

	private static InetAddress hostAddress(String hostName, boolean allowDnsResolution) {
		if (hostName != null && (allowDnsResolution || isIpLiteral(hostName))) {
			try {
				return InetAddress.getByName(hostName);
			}
			catch (UnknownHostException ex) {
				// do not return loopback
			}
		}
		return null;
	}

	/**
	 * Check if the given host name is an IP literal. {@code true} only for forms
	 * {@link InetAddress#getByName(String)} treats as numeric IP addresses (no DNS),
	 * avoiding resolution for host names.
	 * <p>
	 * Upstream additionally requires a {@code '.'}, which excludes the bare-decimal form
	 * the JDK accepts: {@code 2130706433} is {@code 127.0.0.1} and reached loopback
	 * through the released jar. Measured on JDK 8, every form the JDK parses numerically
	 * is either digits-and-dots or contains a {@code ':'} -- it rejects the hex forms
	 * ({@code 0x7f000001}) outright and reads a leading zero as decimal rather than
	 * octal -- so dropping that requirement admits exactly the numeric forms and no
	 * host name.
	 */
	private static boolean isIpLiteral(String hostName) {
		if (hostName.indexOf(':') >= 0) {
			return true;
		}
		for (int i = 0; i < hostName.length(); i++) {
			char c = hostName.charAt(i);
			if (c != '.' && !Character.isDigit(c)) {
				return false;
			}
		}
		return true;
	}

}
