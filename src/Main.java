import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Scanner;
import java.util.logging.Logger;

public class Main {
	static final Logger logger = Logger.getLogger(Main.class.getCanonicalName()); 
	public static void main(String... args) throws Exception {
		int port = args.length > 0 ? Integer.parseInt(args[0]) : 8880;
		logger.info("web server is started. port = " + port);
		try (ServerSocket serverSocket = new ServerSocket()) {
			serverSocket.setReuseAddress(true);
			serverSocket.bind(new InetSocketAddress(port));
			for (boolean running = true; running;) {
				try (Socket socket = serverSocket.accept();
						InputStream in = socket.getInputStream();
						Scanner scanner = new Scanner(in);
						OutputStream out = socket.getOutputStream()) {
					String[] items = scanner.nextLine().split("[\\s?]+");
					logger.info(Arrays.toString(items));
					StringBuilder response = new StringBuilder();
					switch(items[1]) {
					case "/quit":
						response.append("shutdown server");
						running = false;
						break;
					default:
						response.append("test");
						break;
					}
					out.write(("HTTP/1.0 200 OK\r\nDate: " + ZonedDateTime.now().format(DateTimeFormatter.RFC_1123_DATE_TIME) + "\r\nContent-Type: text/html\r\n\r\n" + response).getBytes());
				}
			}
		}
		logger.info("web server is stoped.");
	}
}
