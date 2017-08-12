import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebInitParam;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.PostMethod;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

/**
 * Servlet implementation class OAuthServlet
 */
@WebServlet(name = "oauth", urlPatterns = { "/oauth", "/oauth/*" }, initParams = { // clientId is 'Consumer Key' in the Remote Access UI
		@WebInitParam(name = "clientId", value = "3MVG9d8..z.hDcPLns0FEP7vMhNDlSVdOEGgVe_C5ka0KHsB.ah8WAPyTJejMl776Px3rDQUE.PcwRdBc0OTW"),
		// clientSecret is 'Consumer Secret' in the Remote Access UI
		@WebInitParam(name = "clientSecret", value = "3115384792255172100"),
		// This must be identical to 'Callback URL' in the Remote Access UI
		@WebInitParam(name = "redirectUri", value = "https://localhost:8443/OAuthServlet/oauth/_callback"),
		@WebInitParam(name = "environment", value = "https://login.salesforce.com"), })
public class OAuthServlet extends HttpServlet {
	public static final String id_token = "https://login.salesforce.com";
	public static final String[] id_token_parts = id_token.split("\\.");
	public static final String MODULUS = "hsqiqMXZmxJHzWfZwbSffKfc9YYMxj83-aWhA91jtI8k-GMsEB6mtoNWLP6vmz6x6BQ8Sn6kmn65n1IGCIlWxhPn9yqfXBDBaHFGYED9bBloSEMFnnS9-ACsWrHl5UtDQ3nh-VQTKg1LBmjJMmAOHdBLoUikfpx8fjA1LfDn_1iNWnguj2ehgjWCuTn64UdUd84YNcfO8Ha0TAhWHOhkiluMyzGS0dtN0h8Ybyi5oL6Bf1sfhtOncUh1JuWMcmvICbGEkA_0vBbMp9nCvXdMlpzMOCIoYYkQ-25SRZ0GpIr_oBIZByEm1XaJIqNXoC7qJ95iAyWkUiSegY_IcBV3nMXr-kDNn9Vm2cgLEJGymOiDQKH8g7VjraCIrqWPD3DWv3Z6RsExs6i0gG3JU9cVVFwz87d05_yk3L5ubWb96uxsP9rkwZ3h8eJTfFrgMhk1ZwR-63Dk3ZLYisiAU0zKgr4vQ9qsCNPqDg0rkeqOY5k7Gy201_wh6Sw5dCNTTGmZZ1rNE-gyDu4-a1H40n8f2JFiH-xIOD9-w8HGYOu_oGlobK2KvzFYHTk-w7vtfhZ0j96UkjaBhVjYSMi4hf43xNbB4xJoHhHLESABLp9IYDlnzBeBXKumXDO5aRk3sFAEAWxj57Ec_DyK6UwXSR9Xqji5a1lEArUdFPYzVZ_YCec";
	public static final String EXPONENT = "AQAB";
	public static final String ID_TOKEN_HEADER = base64UrlDecode(id_token_parts[0]);
	public static final String ID_TOKEN_PAYLOAD = base64UrlDecode(id_token_parts[1]);
	public static final byte[] ID_TOKEN_SIGNATURE = base64UrlDecodeToBytes(id_token_parts[2]);
	private static final long serialVersionUID = 1L;
	private static final String ACCESS_TOKEN = "ACCESS_TOKEN";
	private static final String INSTANCE_URL = "INSTANCE_URL";
	private static final String ID_TOKEN="id_token";

	private String clientId = null;
	private String clientSecret = null;
	private String redirectUri = null;
	private String environment = null;
	private String authUrl = null;
	private String tokenUrl = null;

	/**
	 * @see HttpServlet#HttpServlet()
	 */
	public static String base64UrlDecode(String input) {
		byte[] decodedBytes = base64UrlDecodeToBytes(input);
		String result = new String(decodedBytes, StandardCharsets.UTF_8);
		return result;
	}

	public static byte[] base64UrlDecodeToBytes(String input) {
		Base64 decoder = new Base64(-1, null, true);
		byte[] decodedBytes = decoder.decode(input);

		return decodedBytes;
	}

	public static void main(String args[]) {
		System.out.println("hello");
		dumpJwtInfo();
		System.out.println("hello2");
		validateToken();
	}

	public static void dump(String data) {
		System.out.println(data);
	}

	public static void dumpJwtInfo() {
		dump(ID_TOKEN_HEADER);
		dump(ID_TOKEN_PAYLOAD);
	}

	public static void validateToken() {
		PublicKey publicKey = getPublicKey(MODULUS, EXPONENT);
		byte[] data = (id_token_parts[0] + "." + id_token_parts[1]).getBytes(StandardCharsets.UTF_8);

		try {
			boolean isSignatureValid = verifyUsingPublicKey(data, ID_TOKEN_SIGNATURE, publicKey);
			System.out.println("isSignatureValid: " + isSignatureValid);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}

	}

	public static PublicKey getPublicKey(String MODULUS, String EXPONENT) {
		byte[] nb = base64UrlDecodeToBytes(MODULUS);
		byte[] eb = base64UrlDecodeToBytes(EXPONENT);
		BigInteger n = new BigInteger(1, nb);
		BigInteger e = new BigInteger(1, eb);

		RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(n, e);
		try {
			PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(rsaPublicKeySpec);

			return publicKey;
		} catch (Exception ex) {
			throw new RuntimeException("Cant create public key", ex);
		}
	}

	private static boolean verifyUsingPublicKey(byte[] data, byte[] signature, PublicKey pubKey)
			throws GeneralSecurityException {
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initVerify(pubKey);
		sig.update(data);

		return sig.verify(signature);
	}

	public void init() throws ServletException {
		clientId = this.getInitParameter("clientId");
		clientSecret = this.getInitParameter("clientSecret");
		redirectUri = this.getInitParameter("redirectUri");
		environment = this.getInitParameter("environment");

		try {
			authUrl = environment + "/services/oauth2/authorize?response_type=code&scope=openid&client_id=" + clientId
					+ "&redirect_uri=" + URLEncoder.encode(redirectUri, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new ServletException(e);
		}
		tokenUrl = environment + "/services/oauth2/token";
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		String accessToken = (String) request.getSession().getAttribute(ACCESS_TOKEN);
		String userIdToken;
		if (accessToken == null) {
			String instanceUrl = null;
			System.out.println("Redirecting to Authorization end point =" + authUrl);
			if (request.getRequestURI().endsWith("oauth")) {
				response.sendRedirect(authUrl);
				return;
			} else {
				System.out.println("Successful Authorisation-Callback Received");

				String code = request.getParameter("code");

				HttpClient httpclient = new HttpClient();

				PostMethod post = new PostMethod(tokenUrl);
				post.addParameter("code", code);
				post.addParameter("grant_type", "authorization_code");
				post.addParameter("client_id", clientId);
				post.addParameter("client_secret", clientSecret);
				post.addParameter("redirect_uri", redirectUri);

				try {
					httpclient.executeMethod(post);

					try {
						JSONObject authResponse = new JSONObject(
								new JSONTokener(new InputStreamReader(post.getResponseBodyAsStream())));
						System.out.println("AUTH Response:" + authResponse.toString(2));

						accessToken = authResponse.getString("access_token");
						instanceUrl = authResponse.getString("instance_url");
						userIdToken = authResponse.getString(ID_TOKEN);
																		
						System.out.println("Acess Token Acquired" + accessToken);
						System.out.println("ID Token =" + userIdToken);
						
						// Decoding id_token.
						System.out.println("ID Token header = " + new String(Base64.decodeBase64(userIdToken.split("\\.")[0])));
						System.out.println("ID Token Payload = " + new String(Base64.decodeBase64(userIdToken.split("\\.")[1])));
						
					} catch (JSONException e) {
						e.printStackTrace();
						throw new ServletException(e);
					}
				} finally {
					post.releaseConnection();
				}
			}
			request.getSession().setAttribute(ACCESS_TOKEN, accessToken);
			request.getSession().setAttribute(INSTANCE_URL, instanceUrl);
		}
		// response.getWriter().append("Served at:
		// ").append(request.getContextPath());
	}
}
