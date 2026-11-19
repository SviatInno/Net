using FEDept.BackendCourse.GroupA1.Api.Template.Features.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Features.Registration;
using FEDept.BackendCourse.GroupA1.Api.Template.Users;
using Microsoft.EntityFrameworkCore;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Data;

public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();

    public DbSet<RegistrationChallenge> RegistrationChallenges => Set<RegistrationChallenge>();

    public DbSet<LoginChallenge> LoginChallenges => Set<LoginChallenge>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>(user =>
        {
            user.ToTable("users");
            user.HasKey(u => u.Id);
            user.Property(u => u.Id).HasColumnName("id").ValueGeneratedNever();
            user.Property(u => u.Email).HasColumnName("email").HasMaxLength(254).IsRequired();
            user.HasIndex(u => u.Email).IsUnique().HasDatabaseName("ux_users_email");
            user.Property(u => u.PasswordHash).HasColumnName("password_hash").HasMaxLength(256).IsRequired();
            user.Property(u => u.Status)
                .HasColumnName("status")
                .HasMaxLength(16)
                .HasConversion(s => UserStatusNames.ToName(s), s => UserStatusNames.FromName(s));
            user.Property(u => u.CreatedAt).HasColumnName("created_at");
            user.Property(u => u.UpdatedAt).HasColumnName("updated_at");
        });

        modelBuilder.Entity<RegistrationChallenge>(challenge =>
        {
            challenge.ToTable("registration_challenges");
            challenge.HasKey(c => c.Id);
            challenge.Property(c => c.Id).HasColumnName("id").ValueGeneratedNever();
            challenge.Property(c => c.UserId).HasColumnName("user_id");
            challenge.HasOne(c => c.User)
                .WithMany()
                .HasForeignKey(c => c.UserId)
                .OnDelete(DeleteBehavior.Cascade);
            // One challenge per user: a resend re-issues it in place.
            challenge.HasIndex(c => c.UserId).IsUnique().HasDatabaseName("ux_registration_challenges_user_id");
            challenge.Property(c => c.Method)
                .HasColumnName("method")
                .HasMaxLength(16)
                .HasConversion(
                    m => m == ConfirmationMethod.MagicLink ? "magic_link" : "otp",
                    m => m == "magic_link" ? ConfirmationMethod.MagicLink : ConfirmationMethod.Otp);
            challenge.Property(c => c.SecretHash).HasColumnName("secret_hash").IsRequired();
            // Magic link challenges are looked up by the HMAC of the token.
            challenge.HasIndex(c => c.SecretHash).HasDatabaseName("ix_registration_challenges_secret_hash");
            challenge.Property(c => c.ExpiresAt).HasColumnName("expires_at");
            challenge.Property(c => c.Attempts).HasColumnName("attempts");
            challenge.Property(c => c.LastSentAt).HasColumnName("last_sent_at");
            challenge.Property(c => c.ConsumedAt).HasColumnName("consumed_at");
            challenge.Property(c => c.Version).HasColumnName("version").IsConcurrencyToken();
            challenge.Ignore(c => c.IsExhausted);
        });

        modelBuilder.Entity<LoginChallenge>(challenge =>
        {
            challenge.ToTable("login_challenges");
            challenge.HasKey(c => c.Id);
            challenge.Property(c => c.Id).HasColumnName("id").ValueGeneratedNever();
            challenge.Property(c => c.UserId).HasColumnName("user_id");
            challenge.HasOne<User>()
                .WithMany()
                .HasForeignKey(c => c.UserId)
                .OnDelete(DeleteBehavior.Cascade);
            // Named overloads: two separate indexes on the same column.
            challenge.HasIndex(c => c.UserId, "ix_login_challenges_user_id");
            // At most one unconsumed attempt per user; also serves "find the open attempt of a user".
            challenge.HasIndex(c => c.UserId, "ux_login_challenges_user_id_open")
                .IsUnique()
                .HasFilter("consumed_at IS NULL");
            challenge.Property(c => c.Method)
                .HasColumnName("method")
                .HasMaxLength(16)
                .HasConversion(m => LoginChallengeMethods.ToName(m), m => LoginChallengeMethods.FromName(m));
            challenge.Property(c => c.SecretHash).HasColumnName("secret_hash").IsRequired();
            challenge.Property(c => c.Attempts).HasColumnName("attempts");
            challenge.Property(c => c.CreatedAt).HasColumnName("created_at");
            challenge.Property(c => c.LastSentAt).HasColumnName("last_sent_at");
            challenge.Property(c => c.ConsumedAt).HasColumnName("consumed_at");
            challenge.Property(c => c.ConsumedReason)
                .HasColumnName("consumed_reason")
                .HasMaxLength(32)
                .HasConversion(
                    r => r == null ? null : LoginChallengeMethods.ReasonName(r.Value),
                    r => r == null ? null : LoginChallengeMethods.ReasonFromName(r));
            challenge.Ignore(c => c.ExpiresAt);
            challenge.Ignore(c => c.ResendAllowedAt);
        });
    }
}
