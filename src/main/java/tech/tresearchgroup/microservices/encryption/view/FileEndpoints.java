package tech.tresearchgroup.microservices.encryption.view;

import io.activej.csp.file.ChannelFileWriter;
import io.activej.http.*;
import io.activej.inject.annotation.Provides;
import io.activej.inject.module.AbstractModule;
import io.activej.promise.Promisable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jetbrains.annotations.NotNull;
import tech.tresearchgroup.microservices.encryption.controller.KeyManager;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.UUID;
import java.util.concurrent.Executor;

import static java.util.concurrent.Executors.newSingleThreadExecutor;

public class FileEndpoints extends AbstractModule {
    @Provides
    public RoutingServlet servlet() {
        return RoutingServlet.create()
            .map(HttpMethod.POST, "/v1/:algorithm/:bit/:factory", this::handleUpload);
    }

    @Provides
    static Executor executor() {
        return newSingleThreadExecutor();
    }

    public @NotNull Promisable<HttpResponse> handleUpload(HttpRequest httpRequest) {
        try {
            UUID uuid = UUID.randomUUID();
            Path file = new File("temp/" + uuid + ".tmp").toPath();
            String password = httpRequest.getQueryParameter("password");
            String salt = httpRequest.getQueryParameter("salt");
            int bit = Integer.parseInt(httpRequest.getPathParameter("bit"));
            String algorithm = httpRequest.getPathParameter("algorithm");
            String factory = httpRequest.getPathParameter("factory");
            if(password == null || salt == null) {
                return HttpResponse.ofCode(500);
            }
            return httpRequest.handleMultipart(MultipartDecoder.MultipartDataHandler.file(fileName ->
                    ChannelFileWriter.open(executor(), file)))
                .map($ -> encrypt(file, algorithm, factory, bit, password, salt));
        } catch (Exception e) {
            e.printStackTrace();
            return HttpResponse.ofCode(500);
        }
    }

    private HttpResponse encrypt(Path path, String algorithm, String factory, int bit, String password, String salt) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
        byte [] buffer = new byte[1024];
        Cipher cipher = Cipher.getInstance(algorithm, new BouncyCastleProvider());
        SecretKey secretKey = KeyManager.getKeyFromPassword(password, salt, algorithm, bit, factory);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        InputStream in = new FileInputStream(path.toFile());
        int sizeRead;
        while ((sizeRead = in.read(buffer)) != -1) {
            cipher.update(buffer, 0, sizeRead);
        }
        in.close();

        byte[] encrypted = cipher.doFinal();
        if(!path.toFile().delete()) {
            System.err.println("Failed to delete: " + path);
        }
        return HttpResponse.ok200().withBody(encrypted);
    }
}
