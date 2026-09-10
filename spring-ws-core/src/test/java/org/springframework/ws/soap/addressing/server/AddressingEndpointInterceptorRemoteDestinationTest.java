/*
 * Copyright 2005-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.ws.soap.addressing.server;

import static org.assertj.core.api.Assertions.*;
import static org.easymock.EasyMock.*;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import javax.xml.soap.MessageFactory;
import javax.xml.soap.MimeHeaders;
import javax.xml.soap.SOAPConstants;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.ws.context.DefaultMessageContext;
import org.springframework.ws.context.MessageContext;
import org.springframework.ws.soap.SoapMessage;
import org.springframework.ws.soap.addressing.messageid.MessageIdStrategy;
import org.springframework.ws.soap.addressing.version.Addressing10;
import org.springframework.ws.soap.saaj.SaajSoapMessage;
import org.springframework.ws.soap.saaj.SaajSoapMessageFactory;
import org.springframework.ws.transport.WebServiceConnection;
import org.springframework.ws.transport.WebServiceMessageSender;

/**
 * Regression tests for CVE-2026-40999: a peer-supplied {@code wsa:ReplyTo} /
 * {@code wsa:FaultTo} address must not be able to make the server open an outbound
 * connection to an internal destination.
 * <p>
 * Every case drives the real interceptor, so it compiles and runs against the unpatched
 * baseline too. There, the blocked vectors open a connection and the mock fails on an
 * unexpected {@code createConnection}.
 * <p>
 * The address table is upstream's, lifted from its
 * {@code AbstractHttpWebServiceMessageSenderTests}.
 *
 * @author Moderne Backpatch Alliance
 */
class AddressingEndpointInterceptorRemoteDestinationTest {

	private static final String[] BLOCKED = { "http://127.0.0.1:8080/x", "http://169.254.169.254/latest/meta-data/",
			"http://LocalHost/x", "http://internal.localhost/x", "http://[::1]/x", "http://[fe80::1]/x",
			"http://0.0.0.0/x", "http://192.168.0.1/x", "http://10.0.0.1/x", "http://172.16.0.1/x",
			"http://[0:0:0:0:0:ffff:127.0.0.1]/x", "http://169.254.1.2/x", "http:opaque",
			// Bare-decimal literals. The JDK resolves these without DNS and upstream's own
			// screen misses them, because it requires a '.' before treating a host as a
			// literal: 2130706433 is 127.0.0.1, 3232235777 is 192.168.1.1, and 2852039166
			// is the cloud metadata address. All three reached a real loopback listener
			// through the released jar.
			"http://2130706433/latest/meta-data/", "http://3232235777/x", "http://2852039166/x",
			// RFC 3986 makes the scheme case-insensitive, so a sender that lower-cases it
			// would hand this straight through a case-sensitive screen.
			"HTTP://169.254.169.254/latest/meta-data/", "HttpS://10.0.0.1/x",
			// The DNS root dot. These resolve to the loopback address exactly as the
			// undotted forms do, and upstream's localhost guard -- a string comparison --
			// matches neither. http://localhost./ reached a real loopback listener
			// through the released jar.
			"http://localhost./x", "http://LOCALHOST./x", "http://internal.localhost./x" };

	// Public destinations, including a public IP literal so the guard does not depend on
	// DNS being reachable from the build.
	// NOT screened, deliberately, and not asserted either way: IPv6 private ranges
	// (fc00::/7, fec0::/10) and the shared address space 100.64.0.0/10. Upstream scopes its
	// private-range check to IPv4 by name and by javadoc, and this candidate holds that line
	// rather than inventing a stricter policy. See notes: in the manifest. If you are here
	// because you want to screen them, that is a change to the POLICY and needs the operator,
	// not a test edit.

	private static final String[] ALLOWED = { "http://example.com/business/client1", "https://example.com/path",
			"http://93.184.216.34/x",
			// A public name in fully-qualified form is still a public name: stripping the
			// root dot must not turn this into a rejection.
			"http://example.com./path" };

	private static final String REQUEST = "<S:Envelope xmlns:S=\"http://www.w3.org/2003/05/soap-envelope\" "
			+ "xmlns:wsa=\"http://www.w3.org/2005/08/addressing\">" //
			+ "<S:Header>" //
			+ "<wsa:MessageID>http://example.com/someuniquestring</wsa:MessageID>" //
			+ "<wsa:%1$s><wsa:Address>%2$s</wsa:Address></wsa:%1$s>" //
			+ "<wsa:To S:mustUnderstand=\"true\">mailto:fabrikam@example.com</wsa:To>" //
			+ "<wsa:Action>http://example.com/fabrikam/mail/Delete</wsa:Action>" //
			+ "</S:Header>" //
			+ "<S:Body><f:Delete xmlns:f=\"http://example.com/fabrikam\"><f:maxCount>42</f:maxCount></f:Delete></S:Body>" //
			+ "</S:Envelope>";

	private MessageFactory messageFactory;

	@BeforeEach
	void createMessageFactory() throws Exception {
		messageFactory = MessageFactory.newInstance(SOAPConstants.SOAP_1_2_PROTOCOL);
	}

	@Test
	void rejectsPeerSuppliedInternalReplyTo() throws Exception {

		for (String address : BLOCKED) {

			WebServiceMessageSender senderMock = createMock(WebServiceMessageSender.class);
			MessageIdStrategy strategyMock = createMock(MessageIdStrategy.class);
			MessageContext context = createContext("ReplyTo", address);

			AddressingEndpointInterceptor interceptor = newInterceptor(senderMock, strategyMock);
			expect(strategyMock.newMessageId((SoapMessage) context.getResponse())).andReturn(new URI("uid:1234"));
			expect(senderMock.supports(URI.create(address))).andReturn(true).anyTimes();
			replay(strategyMock, senderMock);

			boolean result = interceptor.handleResponse(context, null);

			assertThat(result).as("out-of-band reply to <%s>", address).isFalse();
			assertThat(((SoapMessage) context.getResponse()).getSoapBody().hasFault())
					.as("reply to <%s> is refused with a fault rather than delivered", address).isTrue();
			verify(strategyMock, senderMock);
		}
	}

	@Test
	void rejectsPeerSuppliedInternalFaultTo() throws Exception {

		String address = "http://169.254.169.254/latest/meta-data/";
		WebServiceMessageSender senderMock = createMock(WebServiceMessageSender.class);
		MessageIdStrategy strategyMock = createMock(MessageIdStrategy.class);
		MessageContext context = createContext("FaultTo", address);
		((SaajSoapMessage) context.getResponse()).getSoapBody().addServerOrReceiverFault("Error", Locale.ENGLISH);

		AddressingEndpointInterceptor interceptor = newInterceptor(senderMock, strategyMock);
		expect(strategyMock.newMessageId((SoapMessage) context.getResponse())).andReturn(new URI("uid:1234"));
		expect(senderMock.supports(URI.create(address))).andReturn(true).anyTimes();
		replay(strategyMock, senderMock);

		boolean result = interceptor.handleFault(context, null);

		assertThat(result).isFalse();
		verify(strategyMock, senderMock);
	}

	@Test
	void stillDeliversToPeerSuppliedPublicReplyTo() throws Exception {

		for (String address : ALLOWED) {

			WebServiceMessageSender senderMock = createMock(WebServiceMessageSender.class);
			MessageIdStrategy strategyMock = createMock(MessageIdStrategy.class);
			WebServiceConnection connectionMock = createMock(WebServiceConnection.class);
			MessageContext context = createContext("ReplyTo", address);
			SaajSoapMessage response = (SaajSoapMessage) context.getResponse();

			URI uri = URI.create(address);
			AddressingEndpointInterceptor interceptor = newInterceptor(senderMock, strategyMock);
			expect(strategyMock.newMessageId((SoapMessage) context.getResponse())).andReturn(new URI("uid:1234"));
			expect(senderMock.supports(uri)).andReturn(true).anyTimes();
			expect(senderMock.createConnection(uri)).andReturn(connectionMock);
			connectionMock.send(response);
			connectionMock.close();
			replay(strategyMock, senderMock, connectionMock);

			boolean result = interceptor.handleResponse(context, null);

			assertThat(result).as("out-of-band reply to <%s>", address).isFalse();
			assertThat(context.hasResponse()).as("reply to <%s> was handed to the sender", address).isFalse();
			verify(strategyMock, senderMock, connectionMock);
		}
	}

	private AddressingEndpointInterceptor newInterceptor(WebServiceMessageSender sender, MessageIdStrategy strategy)
			throws Exception {
		expect(strategy.isDuplicate(isA(URI.class))).andReturn(false).anyTimes();
		return new AddressingEndpointInterceptor(new Addressing10(), strategy,
				new WebServiceMessageSender[] { sender }, new URI("urn:replyAction"), new URI("urn:faultAction"));
	}

	private MessageContext createContext(String header, String address) throws Exception {

		MimeHeaders mimeHeaders = new MimeHeaders();
		mimeHeaders.addHeader("Content-Type", " application/soap+xml");
		byte[] request = String.format(REQUEST, header, address).getBytes(StandardCharsets.UTF_8);
		SaajSoapMessage message = new SaajSoapMessage(
				messageFactory.createMessage(mimeHeaders, new ByteArrayInputStream(request)));
		return new DefaultMessageContext(message, new SaajSoapMessageFactory(messageFactory));
	}

}
