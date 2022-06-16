package lan.demo.oauth2.oauthresourceserver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/test")
public class TestController {
    private static final Logger logger = LoggerFactory.getLogger(TestController.class);
    @GetMapping
    public String test(HttpServletRequest request) {
        logRequest(request);
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication.getPrincipal() instanceof Jwt principal) {
            var name = principal.getClaimAsString("name");
            logger.info("NAME {}", name);
            return "OK: " + name;
        }
        return "OK";
    }

    private void logRequest(HttpServletRequest request) {
        var headers = Collections.list(request.getHeaderNames()).stream()
                .map(it -> it + " = " + request.getHeader(it))
                .collect(Collectors.joining("\n"));
        logger.info("HEADERS {}", headers);
    }
}
