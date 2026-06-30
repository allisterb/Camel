namespace Camel;

using Jint;
using Jint.Native;
using Jint.Native.Object;
using Jint.Runtime.Descriptors;
using Jint.Runtime.Interop;

using Camel.PenTest.Toolkits;

/// <summary>
/// The Jint interop wrapper that gives the fluent Metasploit <see cref="MsfModuleContext"/> its
/// <b>datastore-as-properties</b> sugar (v2 of <c>docs/MetasploitJsApi.md</c>): in a code-mode script,
/// <c>m.RHOSTS = target</c> writes the <c>RHOSTS</c> datastore option (and <c>m.RHOSTS</c> reads it back), as a
/// shorthand for <c>m.Set("RHOSTS", target)</c>.
///
/// It is a thin <see cref="ObjectInstance"/> that <b>delegates every real member</b> (the documented
/// <c>Set</c>/<c>SetMany</c>/<c>Get</c>/<c>RunAsync</c> methods and <c>Module</c>/<c>Type</c>/<c>Options</c>/
/// <c>Keys</c> properties) to a standard <see cref="ObjectWrapper"/> over the context, and only intercepts
/// <i>unknown</i> string property names — routing a write to <see cref="MsfModuleContext.Set"/> and a read of a
/// set option to <see cref="MsfModuleContext.Get"/>. Because it forwards to the default wrapper, it exposes
/// exactly the context's real surface — no <c>Dictionary</c> members (<c>Clear</c>/<c>Count</c>/...) leak in.
/// Implementing <see cref="IObjectWrapper"/> (and overriding <see cref="ToObject"/>) is what lets a delegated
/// method bind to the underlying context rather than to this wrapper when called as <c>m.Set(...)</c>.
///
/// This lives in the server (JS-binding) layer, not the toolkit: <see cref="MsfModuleContext"/> stays Jint-free.
/// It is installed via <c>Options.Interop.WrapObjectHandler</c> in <see cref="PenTestMCPTools"/>.
/// </summary>
public sealed class MsfModuleContextWrapper : ObjectInstance, IObjectWrapper
{
    private readonly MsfModuleContext ctx;
    private readonly ObjectInstance inner;   // the default wrapper exposing the context's real members

    public MsfModuleContextWrapper(Engine engine, MsfModuleContext ctx) : base(engine)
    {
        this.ctx = ctx;
        inner = (ObjectInstance)ObjectWrapper.Create(engine, ctx);
    }

    /// <summary>Installs the interop hook on <paramref name="options"/> so an <see cref="MsfModuleContext"/> is
    /// wrapped for datastore-as-properties sugar and every other CLR object marshals through the default wrapper.
    /// Called from <c>PenTestMCPTools</c>; also the seam offline tests configure an engine through.</summary>
    public static void Install(Options options) =>
        options.Interop.WrapObjectHandler = (engine, target, type) =>
            target is MsfModuleContext ctx
                ? new MsfModuleContextWrapper(engine, ctx)
                : ObjectWrapper.Create(engine, target, type);

    // IObjectWrapper.Target / ToObject: make a delegated method (m.Set / m.RunAsync) resolve its CLR 'this' to the
    // context, not to this wrapper — without these, Jint coerces the wrapper to an ExpandoObject and the call fails.
    public object Target => ctx;
    public override object ToObject() => ctx;

    // A property name is a "real member" when the default wrapper has it as an own property (the documented
    // methods/properties); everything else is treated as a datastore option key.
    private bool IsRealMember(JsValue property) => inner.GetOwnProperty(property) != PropertyDescriptor.Undefined;

    public override JsValue Get(JsValue property, JsValue receiver)
    {
        // An unknown property that IS set in the datastore reads back its value; anything else (real members,
        // prototype members like toString) defers to the default wrapper.
        if (property.IsString() && !IsRealMember(property) && ctx.Get(property.AsString()) is { } value)
            return JsValue.FromObject(_engine, value);
        return inner.Get(property, inner);
    }

    public override bool Set(JsValue property, JsValue value, JsValue receiver)
    {
        // An unknown string property is a datastore write (the v2 sugar); real members defer to the default wrapper
        // (so e.g. assigning to a read-only property fails exactly as it would normally).
        if (property.IsString() && !IsRealMember(property))
        {
            ctx.Set(property.AsString(), value.ToObject());
            return true;
        }
        return inner.Set(property, value, inner);
    }

    // Structural delegation so reflection/enumeration sees the context's real members.
    public override PropertyDescriptor GetOwnProperty(JsValue property) => inner.GetOwnProperty(property);
}
