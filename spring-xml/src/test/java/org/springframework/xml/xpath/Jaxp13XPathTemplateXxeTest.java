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

package org.springframework.xml.xpath;

import static org.assertj.core.api.Assertions.*;

import java.io.StringReader;

import javax.xml.transform.sax.SAXSource;
import javax.xml.transform.stream.StreamSource;

import org.junit.jupiter.api.Test;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * Regression tests for CVE-2026-40998: {@link Jaxp13XPathTemplate} must not let
 * attacker-controlled XML on a {@link StreamSource} or a bare {@link SAXSource} reach the JDK
 * default parser, which resolves external entities (XXE — local file disclosure / SSRF).
 *
 * Backpatch-fresh: not present upstream in 3.1.x. Mirrors the hardening added in
 * spring-projects/spring-ws@eb8d66c0995d1e1dd5bfcfb657c8c9de21266d97 (shipped 4.1.4 / 5.0.2),
 * which routes both source shapes through spring-xml's hardened
 * {@code DocumentBuilderFactoryUtils} / {@code TransformerFactoryUtils}. On 3.1.8 as shipped
 * these payloads parse via an unhardened factory and the external entity resolves, so both
 * methods fail without the fix.
 *
 * @see Jaxp13XPathTemplate
 */
class Jaxp13XPathTemplateXxeTest {

	private static final String XXE = "<?xml version=\"1.0\"?>"
			+ "<!DOCTYPE r [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><r>&e;</r>";

	private final XPathOperations template = new Jaxp13XPathTemplate();

	@Test
	void rejectsExternalEntityInStreamSource() {

		assertThatThrownBy(() -> template.evaluateAsString("/r/text()", new StreamSource(new StringReader(XXE))))
				.isInstanceOf(XPathException.class).hasRootCauseInstanceOf(SAXException.class);
	}

	@Test
	void rejectsExternalEntityInSaxSource() {

		SAXSource source = new SAXSource(new InputSource(new StringReader(XXE)));

		assertThatThrownBy(() -> template.evaluateAsString("/r/text()", source))
				.isInstanceOf(XPathException.class).hasRootCauseInstanceOf(SAXException.class);
	}

	@Test
	void evaluatesPlainStreamSource() {

		String xml = "<root><child>expected</child></root>";

		assertThat(template.evaluateAsString("/root/child/text()", new StreamSource(new StringReader(xml))))
				.isEqualTo("expected");
	}

	@Test
	void evaluatesPlainSaxSource() {

		String xml = "<data><item>a</item></data>";
		SAXSource source = new SAXSource(new InputSource(new StringReader(xml)));

		assertThat(template.evaluateAsString("/data/item/text()", source)).isEqualTo("a");
	}

}
