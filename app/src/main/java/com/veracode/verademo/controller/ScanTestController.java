package com.veracode.verademo.controller;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Base64;

import org.apache.commons.text.StringSubstitutor;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.veracode.verademo.utils.Constants;

/*
 * TEST FIXTURE FOR AIKIDO PR SCANNING - DO NOT MERGE.
 *
 * Every method below is intentionally vulnerable so that the Aikido PR scan
 * reports new findings on this pull request. The AWS keys are randomly
 * generated fakes in AWS key format; they are not real credentials.
 */
@Controller
@Scope("request")
public class ScanTestController {
	private static final Logger logger = LogManager.getLogger("VeraDemo:ScanTestController");

	/* START EXAMPLE VULNERABILITY: hardcoded secret (fake) */
	private static final String AWS_ACCESS_KEY_ID = "AKIA3TODIH6CFUHPQVJY";
	private static final String AWS_SECRET_ACCESS_KEY = "6fgUY3RiDGCJ5A+utC/i2gDrhF76qVZ4m+HdCJdt";
	/* END EXAMPLE VULNERABILITY */

	@RequestMapping(value = "/scantest/search", method = RequestMethod.GET)
	@ResponseBody
	public String search(@RequestParam(value = "name") String name) {
		StringBuilder out = new StringBuilder();
		try (Connection connect = DriverManager.getConnection(Constants.create().getJdbcConnectionString());
				Statement stmt = connect.createStatement()) {
			/* START EXAMPLE VULNERABILITY: SQL injection */
			ResultSet rs = stmt.executeQuery("SELECT username FROM users WHERE real_name LIKE '%" + name + "%'");
			/* END EXAMPLE VULNERABILITY */
			while (rs.next()) {
				out.append(rs.getString("username")).append("\n");
			}
		} catch (Exception e) {
			logger.error(e);
		}
		return out.toString();
	}

	@RequestMapping(value = "/scantest/lookup", method = RequestMethod.GET)
	@ResponseBody
	public String lookup(@RequestParam(value = "domain") String domain) throws IOException {
		/* START EXAMPLE VULNERABILITY: command injection */
		Process proc = Runtime.getRuntime().exec(new String[] { "sh", "-c", "nslookup " + domain });
		/* END EXAMPLE VULNERABILITY */
		StringBuilder out = new StringBuilder();
		try (BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
			String line;
			while ((line = br.readLine()) != null) {
				out.append(line).append("\n");
			}
		}
		return out.toString();
	}

	@RequestMapping(value = "/scantest/file", method = RequestMethod.GET)
	@ResponseBody
	public String readFile(@RequestParam(value = "path") String path) throws IOException {
		/* START EXAMPLE VULNERABILITY: path traversal */
		return new String(Files.readAllBytes(new File("/app/reports/" + path).toPath()));
		/* END EXAMPLE VULNERABILITY */
	}

	@RequestMapping(value = "/scantest/restore", method = RequestMethod.POST)
	@ResponseBody
	public String restore(@RequestParam(value = "state") String state) throws Exception {
		/* START EXAMPLE VULNERABILITY: insecure deserialization */
		ObjectInputStream in = new ObjectInputStream(new java.io.ByteArrayInputStream(Base64.getDecoder().decode(state)));
		Object restored = in.readObject();
		/* END EXAMPLE VULNERABILITY */
		return String.valueOf(restored);
	}

	@RequestMapping(value = "/scantest/greet", method = RequestMethod.GET)
	@ResponseBody
	public String greet(@RequestParam(value = "template") String template) {
		/* START EXAMPLE VULNERABILITY: Text4Shell (commons-text 1.9, CVE-2022-42889) */
		return StringSubstitutor.createInterpolator().replace(template);
		/* END EXAMPLE VULNERABILITY */
	}
}
