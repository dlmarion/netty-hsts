package com.github.dlmarion;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Date;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaders.Names;
import io.netty.handler.codec.http.HttpRequestDecoder;
import io.netty.handler.codec.http.HttpResponseEncoder;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.logging.LoggingHandler;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.JdkSslContext;
import io.netty.handler.ssl.NotSslRecordException;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import io.netty.handler.ssl.util.SelfSignedCertificate;

public class HstsTest {
	
	private static class NonSecureHttpHandler extends ChannelInboundHandlerAdapter {
	    private final String redirectAddress;

		public NonSecureHttpHandler(String host, int port) {
	        redirectAddress = "https://" + host + ":" + port + "/secure-me";
		}
	    @Override
	    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
	        ctx.pipeline().remove("ssl");
	        if (cause instanceof NotSslRecordException) {
	            FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,
	                    HttpResponseStatus.MOVED_PERMANENTLY, Unpooled.EMPTY_BUFFER);
	            response.headers().set(Names.LOCATION, redirectAddress);
	            ctx.writeAndFlush(response);
	        }
	    }		
	}
	
	private static class StrictTransportHandler extends SimpleChannelInboundHandler<Object> {

	    public static final String HSTS_HEADER_NAME = "Strict-Transport-Security";
	    private String hstsMaxAge = "max-age=604800";

	    @Override
	    protected void channelRead0(ChannelHandlerContext ctx, Object msg) throws Exception {
            FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,
                    HttpResponseStatus.NOT_FOUND, Unpooled.EMPTY_BUFFER);
            response.headers().set(HSTS_HEADER_NAME, hstsMaxAge);
            ctx.writeAndFlush(response);
	    }
	}
	
    private static final NioEventLoopGroup  boss = new NioEventLoopGroup();
    private static final NioEventLoopGroup workers = new NioEventLoopGroup();
    private static Channel httpChannelHandle;
    private static File clientTrustStoreFile = null;

    @BeforeClass
    public static void before() throws Exception {
        Date begin = new Date();
        Date end = new Date(begin.getTime() + 86400000);
        SelfSignedCertificate ssc = new SelfSignedCertificate("127.0.0.1", begin, end);
        clientTrustStoreFile = ssc.certificate().getAbsoluteFile();
        SslContextBuilder ssl = SslContextBuilder.forServer(ssc.certificate(), ssc.privateKey());
        ssl.clientAuth(ClientAuth.OPTIONAL);
        final SslContext sslCtx = ssl.build();
        
        final ServerBootstrap httpServer = new ServerBootstrap();
        httpServer.group(boss, workers);
        httpServer.channel(NioServerSocketChannel.class);
        httpServer.handler(new LoggingHandler());
        httpServer.childHandler(
	        new ChannelInitializer<SocketChannel>() {
	
	            @Override
	            protected void initChannel(SocketChannel ch) throws Exception {
	            	ch.pipeline().addLast("ssl", sslCtx.newHandler(ch.alloc()));
	            	ch.pipeline().addLast("encoder", new HttpResponseEncoder());
	            	ch.pipeline().addLast("decoder", new HttpRequestDecoder());
	            	ch.pipeline().addLast("non-secure", new NonSecureHttpHandler("127.0.0.1", 54321));
	            	ch.pipeline().addLast("strict", new StrictTransportHandler());
	            }
	
	        });
        
        httpServer.option(ChannelOption.ALLOCATOR, PooledByteBufAllocator.DEFAULT);
        httpServer.option(ChannelOption.SO_BACKLOG, 128);
        httpServer.option(ChannelOption.SO_KEEPALIVE, true);
        httpChannelHandle = httpServer.bind("127.0.0.1", 54321).sync().channel();
    }

    @AfterClass
    public static void after() throws Exception {
    	httpChannelHandle.close();
    }
    
    protected SSLSocketFactory getSSLSocketFactory() throws Exception {
        SslContextBuilder builder = SslContextBuilder.forClient();
        builder.applicationProtocolConfig(ApplicationProtocolConfig.DISABLED);
        builder.sslProvider(SslProvider.JDK);
        builder.trustManager(clientTrustStoreFile); // Trust the server cert
        SslContext ctx = builder.build();
        JdkSslContext jdk = (JdkSslContext) ctx;
        SSLContext jdkSslContext = jdk.context();
        return jdkSslContext.getSocketFactory();
    }


    @Test
    public void testHttpRequestGet() throws Exception {
        HttpURLConnection.setFollowRedirects(false);
        URL url = new URL("http://127.0.0.1:54321/api");
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("GET");
        int responseCode = con.getResponseCode();
        assertEquals(301, responseCode);
        assertEquals("https://127.0.0.1:54321/secure-me", con.getHeaderField(Names.LOCATION));
    }

    @Test
    public void testHSTSRequestGet() throws Exception {
        String secureMe = "https://127.0.0.1:54321/secure-me";
        URL url = new URL(secureMe);
        HttpsURLConnection.setDefaultSSLSocketFactory(getSSLSocketFactory());
        HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
        con.setHostnameVerifier((host, session) -> true);
        int responseCode = con.getResponseCode();
        assertEquals(404, responseCode);
        assertEquals("max-age=604800", con.getHeaderField(StrictTransportHandler.HSTS_HEADER_NAME));
    }

}
