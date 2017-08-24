package org.eclipse.microprofile.jwt.wfswarm.arquillian;

import java.util.logging.Logger;

import javax.enterprise.inject.spi.Extension;

import org.eclipse.microprofile.jwt.wfswarm.cdi.MPJWTExtension;
import org.jboss.arquillian.container.test.spi.client.deployment.ApplicationArchiveProcessor;
import org.jboss.arquillian.test.spi.TestClass;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.spec.WebArchive;

public class WFSwarmWarArchiveProcessor implements ApplicationArchiveProcessor {
    private static Logger log = Logger.getLogger(WFSwarmWarArchiveProcessor.class.getName());

    @Override
    public void process(Archive<?> appArchive, TestClass testClass) {
        if (!(appArchive instanceof WebArchive)) {
            return;
        }
        log.info("Preparing archive: "+appArchive);
        WebArchive war = WebArchive.class.cast(appArchive);
        war.addAsResource("project-defaults.yml", "/project-defaults.yml")
            .addAsWebInfResource("jwt-roles.properties", "classes/jwt-roles.properties")
            .addAsWebInfResource("WEB-INF/jboss-web.xml", "jboss-web.xml")
            .addAsManifestResource(war.get("/WEB-INF/classes/publicKey.pem").getAsset(), "/MP-JWT-SIGNER")
            .setWebXML("WEB-INF/web.xml")
            ;
        log.info("Augmented war: \n"+war.toString(true));
    }
}
