using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Data;

public static class DbUpdateExceptionExtensions
{
    public static bool IsUniqueViolation(this DbUpdateException exception, string constraintName) =>
        exception.InnerException is PostgresException
        {
            SqlState: PostgresErrorCodes.UniqueViolation,
        } postgres
        && postgres.ConstraintName == constraintName;
}
