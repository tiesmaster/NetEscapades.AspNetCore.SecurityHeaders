using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Mvc.ViewEngines;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Razor.TagHelpers;
using Microsoft.AspNetCore.Routing;
using Moq;
using NetEscapades.AspNetCore.SecurityHeaders.Infrastructure;
using Xunit;

namespace NetEscapades.AspNetCore.SecurityHeaders.TagHelpers.Test
{
    public class AttributeHashTagHelperTests
    {
        const string inlineStyleSnippet = "background: red";
        const string inlineMultiLineStyleSnippet =
@"background: red;
color: blue;";

        const string inlineScriptSnippet = "myScript()";

        [Fact]
        public async Task ProcessAsync_StyleAttribute_GeneratesExpectedOutput()
        {
            // Arrange
            var id = Guid.NewGuid().ToString();
            var tagName = "div";
            var styleAttribute = new TagHelperAttribute("style", new MyHtmlString(inlineStyleSnippet));
            var cspAttribute = new TagHelperAttribute("asp-add-attribute-to-csp", "style");
            var fixture = CreateFixture(id, tagName, new([styleAttribute, cspAttribute]));
            var tagHelper = new AttributeHashTagHelper(HtmlEncoder.Default)
            {
                TargetAttributeName = "style",
                CSPHashType = CSPHashType.SHA256,
                ViewContext = GetViewContext(),
            };

            // Act
            await tagHelper.ProcessAsync(fixture.Context, fixture.Output);

            // Assert
            Assert.Equal(tagName, fixture.Output.TagName);
            Assert.Equal([styleAttribute], fixture.Output.Attributes);
            Assert.Empty(fixture.Output.Content.GetContent());
        }

        [Fact]
        public async Task ProcessAsync_StyleAttribute_AddsHashToHttpContext()
        {
            // Arrange
            var id = Guid.NewGuid().ToString();
            var tagName = "div";
            var styleAttribute = new TagHelperAttribute("style", new MyHtmlString(inlineStyleSnippet));
            var cspAttribute = new TagHelperAttribute("asp-add-attribute-to-csp", "style");
            var fixture = CreateFixture(id, tagName, new([styleAttribute, cspAttribute]));
            var tagHelper = new AttributeHashTagHelper(HtmlEncoder.Default)
            {
                TargetAttributeName = "style",
                CSPHashType = CSPHashType.SHA256,
                ViewContext = GetViewContext(),
            };

            // Act
            await tagHelper.ProcessAsync(fixture.Context, fixture.Output);

            // Assert
            var hash = Assert.Single(tagHelper.ViewContext.HttpContext.GetStyleCSPHashes());
            var expected = "'sha256-MCP66z4xZsFojgSzAEKSw3cor5mYnm49IoGrnIBfEO4='";
            Assert.Equal(expected, hash);
        }

        [Fact]
        public async Task ProcessAsync_StyleAttributeWithMultiLine_AddsHashToHttpContext()
        {
            // Arrange
            var id = Guid.NewGuid().ToString();
            var tagName = "div";
            var styleAttribute = new TagHelperAttribute("style", inlineMultiLineStyleSnippet);
            var cspAttribute = new TagHelperAttribute("asp-add-attribute-to-csp", "style");
            var fixture = CreateFixture(id, tagName, new([styleAttribute, cspAttribute]));
            var tagHelper = new AttributeHashTagHelper(HtmlEncoder.Default)
            {
                TargetAttributeName = "style",
                CSPHashType = CSPHashType.SHA256,
                ViewContext = GetViewContext(),
            };

            // Act
            await tagHelper.ProcessAsync(fixture.Context, fixture.Output);

            // Assert
            var hash = Assert.Single(tagHelper.ViewContext.HttpContext.GetStyleCSPHashes());
            var expected = "'sha256-LttsR6Iu9D+xXbKUxLdRQsojrbhLJ0uRF7Gv7hVwMgk='";
            Assert.Equal(expected, hash);
        }

        [Fact]
        public async Task ProcessAsync_InlineScriptAttribute_GeneratesExpectedOutput()
        {
            // Arrange
            var id = Guid.NewGuid().ToString();
            var tagName = "div";
            var inlineScriptAttribute = new TagHelperAttribute("onclick", inlineScriptSnippet);
            var cspAttribute = new TagHelperAttribute("asp-add-attribute-to-csp", "onclick");
            var fixture = CreateFixture(id, tagName, new([inlineScriptAttribute, cspAttribute]));
            var tagHelper = new AttributeHashTagHelper(HtmlEncoder.Default)
            {
                TargetAttributeName = "onclick",
                CSPHashType = CSPHashType.SHA256,
                ViewContext = GetViewContext(),
            };

            // Act
            await tagHelper.ProcessAsync(fixture.Context, fixture.Output);

            // Assert
            Assert.Equal(tagName, fixture.Output.TagName);
            Assert.Equal([inlineScriptAttribute], fixture.Output.Attributes);
            Assert.Empty(fixture.Output.Content.GetContent());
        }

        [Fact]
        public async Task ProcessAsync_InlineScriptAttribute_AddsHashToHttpContext()
        {
            // Arrange
            var id = Guid.NewGuid().ToString();
            var tagName = "div";
            var inlineScriptAttribute = new TagHelperAttribute("onclick", inlineScriptSnippet);
            var cspAttribute = new TagHelperAttribute("asp-add-attribute-to-csp", "onclick");
            var fixture = CreateFixture(id, tagName, new([inlineScriptAttribute, cspAttribute]));
            var tagHelper = new AttributeHashTagHelper(HtmlEncoder.Default)
            {
                TargetAttributeName = "onclick",
                CSPHashType = CSPHashType.SHA256,
                ViewContext = GetViewContext(),
            };

            // Act
            await tagHelper.ProcessAsync(fixture.Context, fixture.Output);

            // Assert
            var hash = Assert.Single(tagHelper.ViewContext.HttpContext.GetScriptCSPHashes());
            var expected = "'sha256-1lzfyKjJuCLGsHTaOB3al0SElf3ats68l7XOAdrWd+E='";
            Assert.Equal(expected, hash);
        }

        private static Fixture CreateFixture(string id, string tagName, TagHelperAttributeList attributes)
        {
            return new Fixture
            {
                Context = GetTagHelperContext(id, tagName, attributes),
                Output = GetTagHelperOutput(id, tagName, attributes)
            };
        }

        private static ViewContext GetViewContext()
        {
            var actionContext = new ActionContext(new DefaultHttpContext(), new RouteData(), new ActionDescriptor());
            return new ViewContext(actionContext,
                                   Mock.Of<IView>(),
                                   new ViewDataDictionary(new EmptyModelMetadataProvider(), new ModelStateDictionary()),
                                   Mock.Of<ITempDataDictionary>(),
                                   TextWriter.Null,
                                   new HtmlHelperOptions());
        }

        private static TagHelperContext GetTagHelperContext(string id, string tagName, TagHelperAttributeList attributes)
        {
            return new TagHelperContext(
                tagName: tagName,
                allAttributes: attributes,
                items: new Dictionary<object, object>(),
                uniqueId: id);
        }

        private static TagHelperOutput GetTagHelperOutput(string id, string tagName, TagHelperAttributeList attributes)
        {
            return new TagHelperOutput(
               tagName,
               attributes: attributes,
               getChildContentAsync: (useCachedResult, encoder) =>
               {
                   var tagHelperContent = new DefaultTagHelperContent();
                   return Task.FromResult<TagHelperContent>(tagHelperContent);
               });
        }

        private class Fixture
        {
            public TagHelperContext Context { get; set; } = default!;
            public TagHelperOutput Output { get; set; } = default!;
        }

        private class MyHtmlString : IHtmlContent
        {
            private readonly string _value;

            public MyHtmlString(string value)
            {
                _value = value;
            }

            public void WriteTo(TextWriter writer, HtmlEncoder encoder)
            {
                writer.Write(_value);
            }
        }
    }
}
