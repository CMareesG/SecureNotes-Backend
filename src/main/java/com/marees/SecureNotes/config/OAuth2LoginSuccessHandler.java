package com.marees.SecureNotes.config;

import com.marees.SecureNotes.models.AppRole;
import com.marees.SecureNotes.models.Role;
import com.marees.SecureNotes.models.User;
import com.marees.SecureNotes.repository.RoleRepository;
import com.marees.SecureNotes.security.jwt.JwtUtils;
import com.marees.SecureNotes.security.services.UserDetailsImpl;
import com.marees.SecureNotes.service.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.*;

@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private final UserService userService;
    private final JwtUtils jwtUtils;
    private final RoleRepository roleRepository;

    @Value("${frontend.url}")
    private String frontendUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws ServletException, IOException {

        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        String registrationId = oauthToken.getAuthorizedClientRegistrationId();
        DefaultOAuth2User principal = (DefaultOAuth2User) authentication.getPrincipal();
        Map<String, Object> attributes = principal.getAttributes();

        String email = attributes.getOrDefault("email", "").toString();
        String name = attributes.getOrDefault("name", "").toString();

        String username;
        String idAttributeKey;

        if ("github".equals(registrationId)) {
            username = attributes.getOrDefault("login", "").toString();
            idAttributeKey = "id";
        } else if ("google".equals(registrationId)) {
            username = email.split("@")[0];
            idAttributeKey = "sub";
        } else {
            username = "";
            idAttributeKey = "id";
        }

        System.out.println("HELLO OAUTH: " + email + " : " + name + " : " + username);

        userService.findByEmail(email).ifPresentOrElse(user -> {
            setSecurityContext(user, attributes, idAttributeKey, registrationId);
        }, () -> {
            Role role = roleRepository.findByRoleName(AppRole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Default role not found"));

            User newUser = new User();
            newUser.setEmail(email);
            newUser.setUserName(username);
            newUser.setRole(role);
            newUser.setSignUpMethod(registrationId);
            userService.registerUser(newUser);

            setSecurityContext(newUser, attributes, idAttributeKey, registrationId);
        });

        DefaultOAuth2User updatedUser = (DefaultOAuth2User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Map<String, Object> updatedAttributes = updatedUser.getAttributes();
        String updatedEmail = updatedAttributes.get("email").toString();

        User user = userService.findByEmail(updatedEmail).orElseThrow(() -> new RuntimeException("User not found"));
        Set<SimpleGrantedAuthority> authorities = new HashSet<>();
        authorities.add(new SimpleGrantedAuthority(user.getRole().getRoleName().name()));

        UserDetailsImpl userDetails = new UserDetailsImpl(
                user.getUserId(),
                user.getUserName(),
                user.getEmail(),
                null,
                false,
                authorities
        );

        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

        String targetUrl = UriComponentsBuilder.fromUriString(frontendUrl + "/oauth2/redirect")
                .queryParam("token", jwtToken)
                .build().toUriString();

        this.setAlwaysUseDefaultTargetUrl(true);
        this.setDefaultTargetUrl(targetUrl);
        super.onAuthenticationSuccess(request, response, authentication);
    }

    private void setSecurityContext(User user, Map<String, Object> attributes, String idAttributeKey, String registrationId) {
        List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(user.getRole().getRoleName().name()));
        DefaultOAuth2User oauthUser = new DefaultOAuth2User(authorities, attributes, idAttributeKey);
        OAuth2AuthenticationToken auth = new OAuth2AuthenticationToken(oauthUser, authorities, registrationId);
        SecurityContextHolder.getContext().setAuthentication(auth);
    }
}
