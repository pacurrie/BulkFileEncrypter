using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Moq;
using NUnit.Framework;

namespace BulkFileEncrypter_Tests
{
    [TestFixture]
    public class EncryptCommandHelper_tests
    {
        private List<string> fileList = new List<string> { "test1", "test2", "bla", "testbla", "testblah", "blahtest", "blah", "testblahtest", "meh" };

        [Test]
        public void WhenGettingListOfFilesWithIgnorePattern_IgnoredFilesAreNotReturned()
        {
            var fileSourceMock = new Mock<BulkFileEncrypter.IFileSource>();
            fileSourceMock.Setup(x => x.GetFilesRecursive(It.IsAny<string>())).Returns(fileList);

            var victim = new BulkFileEncrypter.EncryptCommandHelper(fileSourceMock.Object);

            var list = victim.CreateFileList("test", "blah");
            Assert.IsTrue(list.All(x => !x.Contains("blah")));
        }

        [Test]
        public void WhenGettingListOfFilesWithoutIgnorePattern_AllFilesAreReturned()
        {
            var fileSourceMock = new Mock<BulkFileEncrypter.IFileSource>();
            fileSourceMock.Setup(x => x.GetFilesRecursive(It.IsAny<string>())).Returns(fileList);

            var victim = new BulkFileEncrypter.EncryptCommandHelper(fileSourceMock.Object);

            var list = victim.CreateFileList("test", null);
            Assert.IsTrue(list.SequenceEqual(fileList), "Failed when ignorePattern = null");

            list = victim.CreateFileList("test", string.Empty);
            Assert.IsTrue(list.SequenceEqual(fileList), "Failed when ignorePattern = string.Empty");

            list = victim.CreateFileList("test", "   ");
            Assert.IsTrue(list.SequenceEqual(fileList), "Failed when ignorePattern is whitespace");
        }
    }
}
