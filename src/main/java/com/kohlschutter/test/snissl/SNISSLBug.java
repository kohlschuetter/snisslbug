/*
 * snisslbug
 *
 * Copyright 2023 Christian Kohlschütter
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.kohlschutter.test.snissl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 * Demonstrates a bug in Java's handling of SNI server names. It appears that {@link SNIServerName}
 * settings are persisted across individual client socket connections.
 * <p>
 * The first connection made from the client determines whether/which SNI server names are being
 * sent to the server, regardless of what server names are set later on via the socket-specific
 * {@link SSLParameters}.
 * <p>
 * The only workaround I've found so far is to not reuse {@link SSLContext} for these configurations
 * from the client-side. Note that for the server-side, {@link SNIMatcher}s appear to not be reused
 * across calls, indicating not only an unintuitive but also an inconsistent behavior.
 * <p>
 * The keys/certificates used in the demo are shared across server and client for simplicity.
 * They're already compiled in the resource classpath. You can regenerate the keypair using the
 * following command:
 * <p>
 * {@code keytool -genkeypair -alias snisslbug -keyalg RSA -keysize 2048 -storetype PKCS12 -validity 3650
 * -ext san=dns:example.com -dname "CN=First and Last, OU=Organizational Unit, O=Organization,
 * L=City, ST=State, C=XX" -keystore keypair.p12 -storepass storepass}
 * 
 * @author Christian Kohlschütter
 */
public class SNISSLBug {
  private SSLSocketFactory sslSocketFactory;
  private InetAddress serverAddress;
  private Integer serverPort;
  private SSLContext sslContext;
  private boolean setMatchers = true;

  private static SSLContext initSSLContext() throws NoSuchAlgorithmException, KeyStoreException,
      CertificateException, IOException, UnrecoverableKeyException, KeyManagementException {
    SSLContext context = SSLContext.getInstance("TLS");

    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    KeyStore ks = KeyStore.getInstance("JKS");
    ks.load(SNISSLBug.class.getResourceAsStream("keypair.p12"), "storepass".toCharArray());
    kmf.init(ks, "storepass".toCharArray());

    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory
        .getDefaultAlgorithm());
    tmf.init(ks);

    context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

    return context;
  }

  private void acceptConnection(ServerSocket serverSocket, SSLSocketFactory sf) {
    try (SSLSocket sslSocket = (SSLSocket) sf.createSocket(serverSocket.accept(), null, false)) {
      handleConnection(sslSocket);

      // Uncomment line below to demonstrate that, unlike setServerNames, setSNIMatchers is
      // not reused across calls (will throw an SSLException: "Tag mismatch" from the client-side
      // when an SNI server name is sent without being supported by the server):
      // setMatchers = false;
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private void handleConnection(SSLSocket sslSocket) throws Exception {
    CompletableFuture<Boolean> receivedSNI = new CompletableFuture<Boolean>();

    System.out.println("Setting SNI Matchers: " + setMatchers);
    SSLParameters p = sslSocket.getSSLParameters();
    if (setMatchers) {
      p.setSNIMatchers(Collections.singleton(new SNIMatcher(0) {

        @Override
        public boolean matches(SNIServerName serverName) {
          receivedSNI.complete(true);
          System.out.println("Received SNI server name: " + serverName);
          return true;
        }
      }));
    }
    sslSocket.setSSLParameters(p);

    sslSocket.addHandshakeCompletedListener(new HandshakeCompletedListener() {

      @Override
      public void handshakeCompleted(HandshakeCompletedEvent event) {
        receivedSNI.complete(false);
      }
    });
    sslSocket.startHandshake();
    if (!receivedSNI.get()) {
      System.out.println("Did not receive SNI server name");
    }

    try (OutputStream out = sslSocket.getOutputStream()) {
      out.write(0xff);
    }
  }

  public SNISSLBug() throws UnrecoverableKeyException, KeyManagementException,
      NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException,
      InterruptedException, ExecutionException {
    this.sslContext = initSSLContext();
    this.sslSocketFactory = sslContext.getSocketFactory();
    this.serverAddress = InetAddress.getLoopbackAddress();

    final CompletableFuture<Integer> localPort = new CompletableFuture<>();
    CompletableFuture.runAsync(() -> {
      try (ServerSocket serverSocket = new ServerSocket(0, 50, serverAddress)) {
        localPort.complete(serverSocket.getLocalPort());
        while (!serverSocket.isClosed()) {
          acceptConnection(serverSocket, sslSocketFactory);
        }
      } catch (IOException e) {
        e.printStackTrace();
      }
    });
    this.serverPort = localPort.get();
  }

  public static void main(String[] args) throws Exception {
    SNISSLBug snissl = new SNISSLBug();
    snissl.runDemo(true);
    snissl.runDemo(false);
  }

  private void runDemo(boolean reuseSSLContext) throws Exception {
    System.out.println("**** START DEMO (reuseSSLContext=" + reuseSSLContext + ") ****");
    System.out.println();

    // Uncoment line below to show that the first setting (SSI servername or not) is persisted
    // clientConnect(null, reuseSSLContext); // don't set SSI server name

    clientConnect("snihostName", reuseSSLContext); // set SSI server name

    clientConnect("anotherSnihostName", reuseSSLContext); // set SSI server name to something else

    clientConnect(null, reuseSSLContext); // don't set SSI server name

    System.out.println();
  }

  public void clientConnect(String ssiServerName, boolean reuseSSLContext) throws Exception {
    // Uncomment lines below to show behavior when not reusing the SSLContext for client requests
    if (!reuseSSLContext) {
      sslContext = initSSLContext();
      sslSocketFactory = sslContext.getSocketFactory();
    }

    System.out.println("Connecting to server; setServerName=" + ssiServerName);
    try (SSLSocket clientSocket = (SSLSocket) sslSocketFactory.createSocket(serverAddress,
        serverPort)) {
      SSLParameters p = clientSocket.getSSLParameters();
      System.out.println("Current server names: " + p.getServerNames());
      if (ssiServerName != null) {
        List<SNIServerName> list = Collections.singletonList(new SNIHostName(ssiServerName));
        System.out.println("Setting server names: " + list);
        p.setServerNames(list);
      } else {
        System.out.println("Not setting server names");
      }
      clientSocket.setSSLParameters(p);

      try (InputStream in = clientSocket.getInputStream()) {
        in.read();
      }
    }
    System.out.println();
  }
}
