using System;
using System.ComponentModel;
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

        public static dynamic ConvertTo(this object value, Type type)
        {
            if (value.GetType() == type) return value;

            return (dynamic)TypeDescriptor.GetConverter(type).ConvertFrom(value.ToString());
        }

        public static dynamic ConvertTo<T>(this object value)
        {
           return ConvertTo(value, typeof(T));
        }
    }
}
