using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using TASysOnlineProject.Table;

namespace TASysOnlineProject.Repository.TASysOnline
{
    public interface IMediaRepository : IRepository<MediaTable>
    {
        public Task<List<MediaTable>> FindByContainerNameAsync(string containerName);
    }
}
