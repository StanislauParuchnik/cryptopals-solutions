package cryptopals.challenge13;

public record UserProfile(
        String email,
        Long uid,
        String role
) {
}
