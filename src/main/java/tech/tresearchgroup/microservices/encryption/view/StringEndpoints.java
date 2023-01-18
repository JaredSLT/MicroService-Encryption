package tech.tresearchgroup.microservices.encryption.view;

import io.activej.http.HttpMethod;
import io.activej.http.HttpRequest;
import io.activej.http.HttpResponse;
import io.activej.http.RoutingServlet;
import io.activej.inject.annotation.Provides;
import io.activej.inject.module.AbstractModule;
import io.activej.promise.Promisable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import tech.tresearchgroup.microservices.encryption.controller.KeyManager;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.HashMap;

public class StringEndpoints extends AbstractModule {

    @Provides
    public RoutingServlet servlet() {
        return RoutingServlet.create()
            .map(HttpMethod.GET, "/v1/:algorithm/:bit/:factory", this::encrypt);
    }

    private Promisable<HttpResponse> encrypt(HttpRequest httpRequest) {
        try {
            String string = httpRequest.getQueryParameter("string");
            String password = httpRequest.getQueryParameter("password");
            String salt = httpRequest.getQueryParameter("salt");
            int bit = Integer.parseInt(httpRequest.getPathParameter("bit"));
            String algorithm = httpRequest.getPathParameter("algorithm");
            String factory = httpRequest.getPathParameter("factory");
            if(string == null || password == null || salt == null) {
                return HttpResponse.ofCode(500);
            }
            Cipher cipher = Cipher.getInstance(algorithm, new BouncyCastleProvider());
            long start = System.currentTimeMillis();
            SecretKey secretKey = KeyManager.getKeyFromPassword(password, salt, algorithm, bit, factory);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encrypted = cipher.doFinal(string.getBytes());
            System.out.println(System.currentTimeMillis() - start);
            return HttpResponse.ok200().withBody(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            return HttpResponse.ofCode(500);
        }
    }
}
