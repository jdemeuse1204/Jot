using System.Web.Script.Serialization;

namespace Jot.Tests.Common
{
    public static class Serializer
    {
        public static string ToJSON(object toSerialize)
        {
            return new JavaScriptSerializer().Serialize(toSerialize);
        }

        public static T ToObject<T>(string json) where T : class
        {
            return new JavaScriptSerializer().Deserialize(json, typeof(T)) as T;
        }
    }
}
