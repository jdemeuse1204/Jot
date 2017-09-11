using System;
using System.Reflection;

namespace Jot
{
    internal static class Extensions
    {
        public static bool IsNullable(this Type type)
        {
            return type.IsGenericType && type.GetGenericTypeDefinition() == typeof(Nullable<>);
        }

        public static Type GetParameterType(this ParameterInfo parameter)
        {
            return IsNullable(parameter.ParameterType) ? Nullable.GetUnderlyingType(parameter.ParameterType) : parameter.ParameterType;
        }
    }
}
