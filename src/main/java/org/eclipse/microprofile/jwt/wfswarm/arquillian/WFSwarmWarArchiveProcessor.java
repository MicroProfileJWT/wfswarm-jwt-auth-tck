package org.eclipse.microprofile.jwt.wfswarm.arquillian;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.URL;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Properties;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;

import org.jboss.arquillian.container.test.spi.client.deployment.ApplicationArchiveProcessor;
import org.jboss.arquillian.test.spi.TestClass;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.Node;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;

/**
 * An ApplicationArchiveProcessor for the MP-JWT TCK that includes:
 * - an appropriate project-defaults.yml that sets up the required security domain supporting MP-JWT auth
 * - a jwt-roles.properties that does the group1 to Group1MappedRole mapping
 * - copies /WEB-INF/classes/publicKey.pem to /MP-JWT-SIGNER
 */
public class WFSwarmWarArchiveProcessor implements ApplicationArchiveProcessor {
    private static Logger log = Logger.getLogger(WFSwarmWarArchiveProcessor.class.getName());

    @Override
    public void process(Archive<?> appArchive, TestClass testClass) {
        if (!(appArchive instanceof WebArchive)) {
            return;
        }
        log.info("Preparing archive: "+appArchive);
        // Only augment archives with a publicKey indicating a MP-JWT test
        WebArchive war = WebArchive.class.cast(appArchive);
        Node configProps = war.get("/META-INF/microprofile-config.properties");
        Node publicKeyNode = war.get("/WEB-INF/classes/publicKey.pem");
        Node publicKey4kNode = war.get("/WEB-INF/classes/publicKey4k.pem");
        if (configProps == null && publicKeyNode == null && publicKey4kNode == null) {
            return;
        }
        if (configProps != null) {
            StringWriter sw = new StringWriter();
            InputStream is = configProps.getAsset().openStream();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
                String line = reader.readLine();
                while(line != null) {
                    sw.write(line);
                    sw.write('\n');
                    line = reader.readLine();
                }

            } catch (IOException e) {
                e.printStackTrace();
            }
            log.info("mp-config.props: "+sw.toString());
        } else {
            log.info("NO mp-config.props, adding /META-INF/MP-JWT-SIGNER");
            if(publicKey4kNode != null) {
                war.addAsManifestResource(publicKey4kNode.getAsset(), "MP-JWT-SIGNER");
            } else if(publicKeyNode != null) {
                war.addAsManifestResource(publicKeyNode.getAsset(), "MP-JWT-SIGNER");
            }
        }
        // This allows for test specific web.xml files. Generally this should not be needed.
        String warName = war.getName();
        String webXmlName = "/WEB-INF/" + warName + ".xml";
        URL webXml = WFSwarmWarArchiveProcessor.class.getResource(webXmlName);
        if (webXml != null) {
            war.setWebXML(webXml);
        }
        war.addAsResource("project-defaults.yml", "/project-defaults.yml")
            .addAsWebInfResource("jwt-roles.properties", "classes/jwt-roles.properties")
            ;
        log.info("Augmented war: \n"+war.toString(true));
    }
}
