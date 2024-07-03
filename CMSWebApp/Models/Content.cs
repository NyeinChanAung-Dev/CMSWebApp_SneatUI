using System;
using System.Collections.Generic;

namespace CMSWebApp.Models;

public partial class Content
{
    public int Id { get; set; }

    public string? Title { get; set; }

    public string? BodyText { get; set; }

    public DateTime? CreationTime { get; set; }
}
